/* Copyright 2016 Google Inc. All Rights Reserved.
   Author: waywardgeek@gmail.com (Bill Cox)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License. */

#include <base64.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <token_bind_server.h>
#include <unistd.h>

#define PORT 40000

/* Buffer size for reading/writing requests/responses. */
const size_t kBufferSize = 16384; /* Matches SSL's buffer size */

const char* kCookieSecret = "super-secret-password";

char* login_page =
    "  <h2>LOGIN</h2>\n"
    "  <form method=\"post\" action=\"\">\n"
    "    Username: <input type=\"text\" name=\"user\" size=\"25\" /><br />\n"
    "    Password: <input type=\"password\" name=\"pw\" size=\"10\" /><br "
    "/><br />\n"
    "    <input type=\"submit\" value=\"SEND\" />\n"
    "  </form>";

typedef enum {
  HTTP_POST,
  HTTP_GET,
  HTTP_UNKNOWN,
} HttpRequestType;

struct Connection_st {
  SSL_CTX* ctx;
  SSL* ssl;
  int port;
  int listener_fd;
  int client_fd;
  tbCache* tokbind_cache;
  tbKeyType key_type;
};

typedef struct Connection_st Connection;

struct Cookie_st {
  uint64_t userID;
  uint64_t tokbind_id_hash;
};

typedef struct Cookie_st Cookie;

void* checkedCalloc(size_t num, size_t size) {
  void* p = calloc(num, size);
  if (p == NULL) {
    printf("Out of memory\n");
    exit(1);
  }
  return p;
}

char* copystring(char* source) {
  size_t len = strlen(source);
  char* dest = checkedCalloc(len + 1, sizeof(char));
  strcpy(dest, source);
  return dest;
}

/* Listen on port.  If that is in use, add one and try again. */
Connection* createListeningConnection(int port) {
  Connection* connection = checkedCalloc(1, sizeof(struct Connection_st));
  connection->listener_fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  while (bind(connection->listener_fd, (struct sockaddr*)&addr, sizeof(addr)) <
         0) {
    printf("Could not bind socket on port %u\n", port);
    port++;
    addr.sin_port = htons(port);
  }
  connection->port = port;
  printf("Listening on port %u\n", port);
  if (listen(connection->listener_fd, 1) < 0) {
    printf("Could not listen on port %u\n", port);
    exit(1);
  }
  OPENSSL_init_ssl(
      OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
  connection->ctx = ctx;
  SSL_CTX_use_PrivateKey_file(ctx, "test.key", SSL_FILETYPE_PEM);
  SSL_CTX_use_certificate_file(ctx, "test.crt", SSL_FILETYPE_PEM);
  EC_KEY* ecdh_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
  SSL_CTX_set_tmp_ecdh(ctx, ecdh_key);
  EC_KEY_free(ecdh_key);
  if (!tbTLSLibInit()) {
    printf("Failed to initialize TLS token binding negotiation library\n");
    exit(1);
  }
  if (!tbEnableTLSTokenBindingNegotiation(ctx)) {
    printf("Failed to enable TLS token binding negotiation\n");
    exit(1);
  }
  return connection;
}

/* Wait for a new connection on the port. */
void waitForConnection(Connection* connection) {
  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);
  connection->client_fd =
      accept(connection->listener_fd, (struct sockaddr*)&addr, &len);
  if (connection->client_fd < 0) {
    printf("Could not accept connection\n");
    exit(1);
  }
  printf("Got new connection\n");
}

void negotiateTLS(Connection* connection) {
  connection->ssl = SSL_new(connection->ctx);
  SSL_set_fd(connection->ssl, connection->client_fd);
  SSL_accept(connection->ssl);
  connection->tokbind_cache = tbCacheCreate();
}

void closeConnection(Connection* connection) {
  printf("closing connection\n");
  tbCacheDestroy(connection->tokbind_cache);
  connection->tokbind_cache = NULL;
  SSL_shutdown(connection->ssl);
  SSL_free(connection->ssl);
  connection->ssl = NULL;
  close(connection->client_fd);
  connection->client_fd = -1;
}

/* This function assumes the entire request is sent in one packet, and not
   split across SSL_read calls.  Also, the maximum request size is limited to
   kBufferSize. */
char* readRequest(Connection* connection) {
  char buffer[kBufferSize];
  int num_bytes = SSL_read(connection->ssl, buffer, kBufferSize);
  if (num_bytes <= 0) {
    printf("Could not read with return val %u\n", num_bytes);
    return NULL;
  }
  buffer[num_bytes] = '\0';
  printf("Here is the message:\n%s\n", buffer);
  return copystring(buffer);
}

HttpRequestType getRequestType(char* request) {
  if (!strncmp(request, "GET", 3)) {
    return HTTP_GET;
  } else if (!strncmp(request, "POST", 4)) {
    return HTTP_POST;
  }
  return HTTP_UNKNOWN;
}

char* getRequestPath(char* request) {
  char* p = strchr(request, ' ');
  if (p == NULL) {
    return NULL;
  }
  char* start = p + 1;
  char* end = strchr(start, ' ');
  if (end == NULL) {
    return NULL;
  }
  char path[kBufferSize];
  memcpy(path, start, end - start);
  path[end - start] = '\0';
  printf("Found path %s\n", path);
  return copystring(path);
}

char* findRequestHeader(char* request, char* name) {
  char* header_end = strstr(request, "\r\n\r\n");
  char* p = strcasestr(request, name);
  if (p == NULL || (header_end != NULL && p > header_end)) {
    return NULL;
  }
  p += strlen(name);
  while (*p == ':' || *p == ' ' || *p == '\t') {
    p++;
  }
  char* start = p;
  while (*p != '\n' && *p != '\r' && *p != '\0') {
    p++;
  }
  char* end = p;
  if (end == start) {
    return NULL;
  }
  /* The + 1 adds a '\0' at the end of the string. */
  char header[kBufferSize];
  memcpy(header, start, end - start);
  header[end - start] = '\0';
  return copystring(header);
}

char* findRequestCookie(char* request, char* name) {
  char* header_end = strstr(request, "\r\n\r\n");
  char* p = strcasestr(request, name);
  if (p == NULL || (header_end != NULL && p > header_end)) {
    return NULL;
  }
  p += strlen(name);
  while (*p == '=' || *p == ' ' || *p == '\t') {
    p++;
  }
  char* start = p;
  while (*p != '\n' && *p != '\r' && *p != '\0') {
    p++;
  }
  char* end = p;
  if (end == start) {
    return NULL;
  }
  /* The + 1 adds a '\0' at the end of the string. */
  char cookie[kBufferSize];
  memcpy(cookie, start, end - start);
  cookie[end - start] = '\0';
  return copystring(cookie);
}

/* Hash the cookie secret and the TokenBindingID to get a 64-bit hash that we
   can embed in the cookie.  Hashing with the cookie secret helps defend
   against collision attacks. */
uint64_t hashTokenBindingIDAndCookieSecret(uint8_t* tokbind_id,
                                           size_t tokbind_id_len) {
  uint8_t hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, tokbind_id, tokbind_id_len);
  SHA256_Update(&sha256, kCookieSecret, strlen(kCookieSecret));
  SHA256_Final(hash, &sha256);
  uint64_t hash64 = 0;
  size_t i;
  for (i = 0; i < sizeof(uint64_t); i++) {
    hash64 = (hash64 << 8) | hash[i];
  }
  return hash64;
}

/* This is where we generate and encrypt the auth cookie.  Here, I just hash
   the secret cookie password with the TokenBindingID to generate the auth
   cookie, but you probably would prefer to create an auth cookie with a
   UserID, etc. */
char* generateAuthCookie(uint8_t* tokbind_id, size_t tokbind_id_len) {
  Cookie cookie;
  /* A real app would do a real userID lookup and verify the password here. */
  cookie.userID = 1234;
  cookie.tokbind_id_hash =
      hashTokenBindingIDAndCookieSecret(tokbind_id, tokbind_id_len);
  /* This is where you would encrypt the cookie, but in this example we
     don't. */
  size_t cookie_string_len = CalculateBase64EscapedLen(sizeof(Cookie), false);
  char* cookie_string = checkedCalloc(cookie_string_len + 1, sizeof(char));
  WebSafeBase64Escape((void*)&cookie, sizeof(Cookie), cookie_string,
                      cookie_string_len, false);
  return cookie_string;
}

bool verifyAuthCookie(char* auth_cookie, uint8_t* tokbind_id,
                      size_t tokbind_id_len) {
  Cookie cookie;
  size_t cookie_len =
      WebSafeBase64Unescape(auth_cookie, (void*)&cookie, sizeof(Cookie));
  if (cookie_len != sizeof(Cookie)) {
    return false;
  }
  /* This is where you would decrypt the cookie, but we don't in this
     example. */
  if (cookie.userID != 1234) {
    /* Wrong user */
    return false;
  }
  uint64_t tokbind_id_hash =
      hashTokenBindingIDAndCookieSecret(tokbind_id, tokbind_id_len);
  if (cookie.tokbind_id_hash != tokbind_id_hash) {
    /* Wrong TokenBindingID */
    return false;
  }
  return true;
}

char* getSetCookieString(char* cookie) {
  char buf[kBufferSize];
  if (cookie == NULL) {
    buf[0] = '\0';
  } else {
    sprintf(buf, "Set-Cookie: auth=%s\r\n", cookie);
  }
  return copystring(buf);
}

void respond(Connection* connection, char* title, char* message, char* cookie) {
  char header[kBufferSize];
  sprintf(header, "<html>\r\n<head><title>%s</title></head>\r\n<body>\r\n",
          title);
  char* footer = "\r\n</body>\r\n</html>\r\n";
  char* set_cookie_string = getSetCookieString(cookie);
  char response[kBufferSize];
  int response_len = sprintf(response,
                             "HTTP/1.1 200 OK\r\n"
                             "Server: example_server\r\n"
                             "%s" /* Cookie string */
                             "Content-Length: %lu\r\n"
                             "Content-Type: text/html\r\n"
                             "Connection: Close\r\n"
                             "\r\n"
                             "%s"  /* header */
                             "%s"  /* message */
                             "%s", /* footer */
                             set_cookie_string,
                             strlen(header) + strlen(message) + strlen(footer),
                             header, message, footer);
  free(set_cookie_string);
  printf("Sending:\n%s\n", response);
  if (SSL_write(connection->ssl, response, response_len) <= 0) {
    printf("Unable to write to SSL connection\n");
    exit(1);
  }
}

void redirect(Connection* connection, char* dest, char* cookie) {
  char response[kBufferSize];
  int response_len =
      sprintf(response,
              "HTTP/1.1 303 See Other\n"
              "Connection: Close\r\n"
              "Location: https://localhost:%u%s\r\n%s\r\n",
              connection->port, dest, getSetCookieString(cookie));
  printf("Sending redirect:\n%s\n", response);
  if (SSL_write(connection->ssl, response, response_len) <= 0) {
    printf("Unable to write to SSL connection\n");
    exit(1);
  }
}

void respondNotFound(Connection* connection) {
  char* response =
      "HTTP/1.1 404 Not Found\n"
      "Connection: Close\r\n\r\n";
  int response_len = strlen(response);
  printf("Sending redirect:\n%s\n", response);
  if (SSL_write(connection->ssl, response, response_len) <= 0) {
    printf("Unable to write to SSL connection\n");
    exit(1);
  }
}

bool getRequestTokenBindingID(char* request, Connection* connection,
                              uint8_t** out_tokbind_id,
                              size_t* out_tokbind_id_len) {
  char* tbheader = findRequestHeader(request, "sec-token-binding");
  if (tbheader == NULL) {
    printf("No token binding header in request\n");
    return false;
  }
  printf("Found token binding header: %s\n", tbheader);
  uint8_t* referred_tokbind_id;
  size_t referred_tokbind_id_len;
  size_t maxlen = strlen(tbheader);
  char* message = checkedCalloc(maxlen, sizeof(char));
  size_t message_len = WebSafeBase64Unescape(tbheader, message, maxlen);
  free(tbheader);
  if (message_len == 0) {
    printf("Could not base64-unencode token binding header\n");
    return false;
  }
  if (tbCacheMessageAlreadyVerified(
          connection->tokbind_cache, (uint8_t*)message, message_len,
          out_tokbind_id, out_tokbind_id_len, &referred_tokbind_id,
          &referred_tokbind_id_len)) {
    if (referred_tokbind_id != NULL) {
      printf(
          "Token binding header with referred TokenBindingID was found in the "
          "cache\n");
    } else {
      printf("Token binding header was found in the cache\n");
    }
    return true;
  }
  uint8_t ekm[TB_HASH_LEN];
  if (!tbGetEKM(connection->ssl, ekm)) {
    printf("Unable to get EKM from TLS connection\n");
    exit(1);
  }
  if (!tbCacheVerifyTokenBindingMessage(
          connection->tokbind_cache, (uint8_t*)message, message_len,
          connection->key_type, ekm, out_tokbind_id, out_tokbind_id_len,
          &referred_tokbind_id, &referred_tokbind_id_len)) {
    printf("Bad token binding header\n");
    return false;
  }
  printf("Verified token binding header\n");
  return true;
}

/* Return true if the request is authenticated with an auth cookie. */
bool requestAuthenticated(char* request, uint8_t* tokbind_id,
                          size_t tokbind_id_len) {
  char* auth_cookie = findRequestCookie(request, "auth");
  if (auth_cookie == NULL) {
    return false;
  }
  bool verified = verifyAuthCookie(auth_cookie, tokbind_id, tokbind_id_len);
  free(auth_cookie);
  return verified;
}

void processRequest(char* request, Connection* connection) {
  uint8_t* tokbind_id;
  size_t tokbind_id_len;
  if (connection->key_type == TB_INVALID_KEY_TYPE) {
    respond(connection, "Warning", "Token binding not negotiated", NULL);
    return;
  }
  if (!getRequestTokenBindingID(request, connection, &tokbind_id,
                                &tokbind_id_len)) {
    respond(connection, "Warning", "No token binding header", NULL);
    return;
  }
  char* path = getRequestPath(request);
  HttpRequestType type = getRequestType(request);
  bool authenticated =
      requestAuthenticated(request, tokbind_id, tokbind_id_len);
  if (strcasecmp(path, "/login") && !authenticated) {
    redirect(connection, "/login", NULL);
  } else if (!strcasecmp(path, "/")) {
    redirect(connection, "/user", NULL);
  } else if (!strcasecmp(path, "/login")) {
    if (type == HTTP_POST) {
      char* auth_cookie = generateAuthCookie(tokbind_id, tokbind_id_len);
      redirect(connection, "/user", auth_cookie);
    } else {
      respond(connection, "Login", login_page, NULL);
    }
  } else if (!strcasecmp(path, "/user")) {
    if (getRequestType(request) != HTTP_GET) {
      respond(connection, "Unsupported Request",
              "We only respond to GET and POST requests", NULL);
      return;
    }
    char* auth_cookie = findRequestCookie(request, "auth");
    if (auth_cookie == NULL) {
      respond(connection, "Login", login_page, NULL);
      return;
    }
    if (!verifyAuthCookie(auth_cookie, tokbind_id, tokbind_id_len)) {
      respond(connection, "Login", login_page, NULL);
      return;
    }
    respond(
        connection, "Home Page",
        "We verified your auth cookie.  You have reached your user home "
        "page.  If this were a real web application, you would see something "
        "cool now.",
        NULL);
  } else {
    respondNotFound(connection);
  }
  free(path);
}

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;
  uint64_t rand_seed = 0; /* This prevents collision attacks on the cache. */
  RAND_seed(&rand_seed, sizeof(uint64_t));
  tbCacheLibInit(
      rand_seed); /* Make sure to pass a true random number in your system */
  Connection* connection = createListeningConnection(PORT);
  do {
    waitForConnection(connection);
    negotiateTLS(connection);
    tbKeyType key_type = TB_INVALID_KEY_TYPE;
    if (!tbTokenBindingEnabled(connection->ssl, &key_type)) {
      printf("Connection failed to negotiate token binding\n");
    } else {
      printf("Connection negotiated token binding with key type %s\n",
             tbGetKeyTypeName(key_type));
    }
    connection->key_type = key_type;
    char* request = readRequest(connection);
    while (request != NULL) {
      processRequest(request, connection);
      closeConnection(connection);
      waitForConnection(connection);
      negotiateTLS(connection);
      free(request);
      request = readRequest(connection);
    }
    closeConnection(connection);
  } while (true);
  return 0;
}
