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
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <token_bind_client.h>
#include <unistd.h>

/* Buffer size for reading/writing requests/responses. */
const size_t kBufferSize = 16384;  /* Matches SSL's buffer size */

typedef enum {
  HTTP_POST,
  HTTP_GET,
  HTTP_UNKNOWN,
} HttpRequestType;

struct Connection_st;
struct Key_st;
struct Oracle_st;
struct Cookie_st;
struct CookieJar_st;
typedef struct Connection_st Connection;
typedef struct Key_st Key;
typedef struct Oracle_st Oracle;
typedef struct Cookie_st Cookie;
typedef struct CookieJar_st CookieJar;

struct Connection_st {
  SSL_CTX* ctx;
  SSL* ssl;
  int port;
  int server_fd;
  tbKeyType key_type;
};

struct Key_st {
  char* etld_plus1;
  char* encoded_key;
  Key* next_key;
  tbKeyType key_type;
};

struct Oracle_st {
  Key* first_key;
};

struct Cookie_st {
  char* hostname;
  char* name;
  char* value;
  Cookie* next_cookie;
};

struct CookieJar_st {
  Cookie* first_cookie;
};

void usage(void) {
  printf(
      "Usage: client get url\n"
      "           e.g. client get https://localhost:40000/user\n"
      "       client post url variables\n"
      "           e.g. client post https://localhost:40000/login "
      "user=john&pw=password\n"
      "Cookies keys are written to a file called cookies\n"
      "Public/private keys are written to a file called key_vault\n");
  exit(1);
}

HttpRequestType parseType(char* type_name) {
  if (!strcasecmp(type_name, "get")) {
    return HTTP_GET;
  }
  if (!strcasecmp(type_name, "post")) {
    return HTTP_POST;
  }
  return HTTP_UNKNOWN;
}

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

/* Parse the host, path, and port number from the url. */
void parseHostPathAndPort(char* url, char** out_hostname, char** out_path,
                          int* out_port) {
  char* hostname;
  char* path;
  int port = 443;
  char* prefix = "https://";
  int prefix_len = strlen(prefix);
  if (strncasecmp(url, prefix, prefix_len)) {
    printf("The url parameter must start with http://\n");
    usage();
  }
  char* p = url + prefix_len;
  char* hostname_start = p;
  p = strpbrk(p, ":/");
  if (p == NULL) {
    hostname = copystring(hostname_start);
    path = copystring("/");
  } else {
    int hostname_len = p - hostname_start;
    hostname = checkedCalloc(hostname_len + 1, sizeof(char));
    memcpy(hostname, hostname_start, hostname_len);
    hostname[hostname_len] = '\0';
    if (*p == ':') {
      p++;
      char* endptr;
      port = strtol(p, &endptr, 10);
      if (endptr == p) {
        printf("Invalid port number\n");
        usage();
      }
      p = endptr;
    }
    if (*p == '\0') {
      path = copystring("/");
    } else {
      if (*p != '/') {
        printf("Expecting / in url\n");
        usage();
      }
      path = copystring(p);
    }
  }
  printf("hostname = %s, path = %s, port=%u\n", hostname, path, port);
  *out_hostname = hostname;
  *out_path = path;
  *out_port = port;
}

void negotiateTLS(Connection* connection) {
  OPENSSL_init_ssl(
      OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  connection->ctx = ctx;
  if (!tbTLSLibInit()) {
    printf("Failed to initialize TLS token binding negotiation library\n");
    exit(1);
  }
  if (!tbEnableTLSTokenBindingNegotiation(ctx)) {
    printf("Failed to enable TLS token binding negotiation\n");
    exit(1);
  }
  connection->ssl = SSL_new(connection->ctx);
  SSL_set_fd(connection->ssl, connection->server_fd);
  SSL_connect(connection->ssl);
  tbKeyType key_type = TB_INVALID_KEY_TYPE;
  if (!tbTokenBindingEnabled(connection->ssl, &key_type)) {
    printf("Connection failed to negotiate token binding\n");
  } else {
    printf("Connection negotiated token binding with key type %s\n",
           tbGetKeyTypeName(key_type));
  }
  connection->key_type = key_type;
}

Connection* openConnection(char* hostname, int port) {
  Connection* connection = checkedCalloc(1, sizeof(Connection));
  connection->server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (connection->server_fd < 0) {
    printf("Could not create socket\n");
    exit(1);
  }
  struct hostent* server = gethostbyname(hostname);
  if (server == NULL) {
    printf("No such host: %s\n", hostname);
    exit(1);
  }
  struct sockaddr_in addr;
  memset(&addr, '\0', sizeof(addr));
  addr.sin_family = AF_INET;
  memcpy(server->h_addr, &addr.sin_addr.s_addr, server->h_length);
  addr.sin_port = htons(port);
  if (connect(connection->server_fd, (struct sockaddr*)&addr, sizeof(addr)) <
      0) {
    printf("Could not connect to %s:%u\n", hostname, port);
    exit(1);
  }
  negotiateTLS(connection);
  return connection;
}

/* Get the "effective top-level domain + 1", or ETLD+1.  This is harder than it
   sounds, because there is a list of exceptions to the rule that this is just
   <server_name>.com (or .edu, etc).  For example, google.com.uk is an eTLD+1,
   which is why we say "effective".  The Chromium source has a good and well
   maintained list of exceptions.  For this example, we just assume there are
   no exceptions. */
char* getETLDPlus1(char* hostname) {
  char* p = strrchr(hostname, '.');
  if (p == NULL) {
    /* Hostname has no ".", so just return the whole hostname. */
    return hostname;
  }
  p = strrchr(p, '.');
  if (p == NULL) {
    /* Hostname has only one ".", so just return the whole hostname. */
    return hostname;
  }
  return p + 1;
}

Key* findKey(Oracle* oracle, char* etld_plus1) {
  Key* key;
  for (key = oracle->first_key;
       key != NULL && strcasecmp(key->etld_plus1, etld_plus1);
       key = key->next_key)
    ;
  return key;
}

char* encodeKey(EVP_PKEY* pkey) {
  /* Get the length first. */
  size_t length = i2d_PrivateKey(pkey, NULL);
  if (length <= 0) {
    printf("Unable to convert pkey to text\n");
    exit(1);
  }
  uint8_t* buf = checkedCalloc(length, sizeof(uint8_t));
  uint8_t* p = buf;
  i2d_PrivateKey(pkey, &p);
  size_t encoded_len = CalculateBase64EscapedLen(length, false);
  char* out = checkedCalloc(encoded_len, sizeof(char));
  WebSafeBase64Escape((char*)buf, length, out, encoded_len, false);
  free(buf);
  return out;
}

EVP_PKEY* decodeKey(char* encoded_key, tbKeyType key_type) {
  uint8_t key_len = strlen(encoded_key) + 1;
  uint8_t* key = checkedCalloc(key_len, sizeof(char));
  key_len = WebSafeBase64Unescape(encoded_key, (char*)key, key_len);
  int type;
  if (key_type == TB_ECDSAP256) {
    type = EVP_PKEY_EC;
  } else {
    type = EVP_PKEY_RSA;
  }
  const uint8_t* p = key;
  EVP_PKEY* pkey = d2i_PrivateKey(type, NULL, &p, key_len);
  free(key);
  return pkey;
}

EVP_PKEY* generateRSA2048Key() {
  EVP_PKEY* pkey = NULL;
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
      EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    printf("Failed to generate RSA key\n");
    exit(1);
  }
  return pkey;
}

EVP_PKEY* generateECDSAP256Key() {
  EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (eckey == NULL || !EC_KEY_generate_key(eckey)) {
    printf("Could not generate EC key\n");
    exit(1);
  }
  EVP_PKEY* pkey = EVP_PKEY_new();
  if (pkey == NULL || !EVP_PKEY_assign_EC_KEY(pkey, eckey)) {
    printf("Could not create EVP_PKEY\n");
    exit(1);
  }
  return pkey;
}

Key* createKey(Oracle* oracle, char* etld_plus1, tbKeyType key_type,
               char* encoded_key) {
  Key* key = checkedCalloc(1, sizeof(Key));
  key->key_type = key_type;
  key->etld_plus1 = copystring(etld_plus1);
  key->encoded_key = copystring(encoded_key);
  key->next_key = oracle->first_key;
  oracle->first_key = key;
  return key;
}

Key* generateKey(Oracle* oracle, char* etld_plus1, tbKeyType key_type) {
  EVP_PKEY* pkey;
  switch (key_type) {
    case TB_RSA2048_PKCS15:
    case TB_RSA2048_PSS:
      pkey = generateRSA2048Key();
      break;
    case TB_ECDSAP256:
      pkey = generateECDSAP256Key();
      break;
    default:
      printf("Unknown key type\n");
      exit(1);
  }
  char* encoded_key;
  encoded_key = encodeKey(pkey);
  EVP_PKEY_free(pkey);
  Key* key = createKey(oracle, etld_plus1, key_type, encoded_key);
  free(encoded_key);
  return key;
}

void getKeyTokenBindingID(Key* key, uint8_t** out_tokbind_id,
                          size_t* out_tokbind_id_len) {
  EVP_PKEY* pkey = decodeKey(key->encoded_key, key->key_type);
  size_t len = i2d_PublicKey(pkey, NULL);
  if (len <= 0) {
    printf("Unable to convert pkey to text\n");
    exit(1);
  }
  uint8_t* buf = checkedCalloc(len, sizeof(uint8_t));
  uint8_t* p = buf;
  i2d_PublicKey(pkey, &p);
  if (!tbConvertDerKeyToTokenBindingID(buf, len, key->key_type, out_tokbind_id,
                                       out_tokbind_id_len)) {
    printf("Unable to convert OpenSSL encoded public key to TokenBindingID\n");
    exit(1);
  }
  free(buf);
  EVP_PKEY_free(pkey);
}

/* Delete the key. */
static void deleteKey(Oracle* oracle, char* etld_plus1) {
  Key* prev_key = NULL;
  Key* key;
  for (key = oracle->first_key;
       key != NULL && strcasecmp(key->etld_plus1, etld_plus1);
       key = key->next_key) {
    prev_key = key;
  }
  if (key == NULL) {
    printf("Key not found\n");
    exit(1);
  }
  if (prev_key == NULL) {
    oracle->first_key = key->next_key;
  } else {
    prev_key->next_key = key->next_key;
  }
  free(key->etld_plus1);
  free(key->encoded_key);
  free(key);
}

/* Find or create a token binding key pair compatible with the negotiated key
   type.  Then return the TokenBindingID for that key. */
void getTokenBindingID(Connection* connection, Oracle* oracle, char* etld_plus1,
                       uint8_t** out_tokbind_id, size_t* out_tokbind_id_len) {
  Key* key = findKey(oracle, etld_plus1);
  if (key != NULL) {
    if (connection->key_type == key->key_type) {
      getKeyTokenBindingID(key, out_tokbind_id, out_tokbind_id_len);
      return;
    }
    /* The server changed key type, so delete the old token binding key and
       create a new one. */
    deleteKey(oracle, etld_plus1);
  }
  /* We have to create a key pair. */
  key = generateKey(oracle, etld_plus1, connection->key_type);
  getKeyTokenBindingID(key, out_tokbind_id, out_tokbind_id_len);
}

void signMessage(Oracle* oracle, char* etld_plus1, uint8_t* message,
                 size_t message_len, uint8_t** out_sig, size_t* out_sig_len) {
  Key* key = findKey(oracle, etld_plus1);
  if (key == NULL) {
    printf("Key not found\n");
    exit(1);
  }
  EVP_PKEY* pkey = decodeKey(key->encoded_key, key->key_type);
  EVP_PKEY_CTX* key_ctx;
  const size_t kMaxSigLen = 3000;  // Big enough for RSA-2048
  size_t sig_len = kMaxSigLen;
  uint8_t buf[kMaxSigLen];
  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  if (!EVP_DigestSignInit(md_ctx, &key_ctx, EVP_sha256(), NULL, pkey) ||
      !tbSetPadding(key->key_type, key_ctx) ||
      !EVP_DigestSignUpdate(md_ctx, message, message_len) ||
      !EVP_DigestSignFinal(md_ctx, buf, &sig_len) ||
      !tbConvertDerSigToTokenBindingSig(buf, sig_len, key->key_type, out_sig,
                                        out_sig_len)) {
    printf("Signing operation failed\n");
    exit(1);
  }
  EVP_PKEY_free(pkey);
  EVP_MD_CTX_free(md_ctx);
}

char* generateTokenBindingHeader(Connection* connection, Oracle* oracle,
                                 char* etld_plus1, char* referred_etld_plus1) {
  uint8_t* tokbind_id;
  size_t tokbind_id_len;
  getTokenBindingID(connection, oracle, etld_plus1, &tokbind_id,
                    &tokbind_id_len);
  uint8_t* referred_tokbind_id = NULL;
  size_t referred_tokbind_id_len = 0;
  if (referred_etld_plus1 != NULL) {
    getTokenBindingID(connection, oracle, referred_etld_plus1,
                      &referred_tokbind_id, &referred_tokbind_id_len);
  }
  uint8_t ekm[TB_HASH_LEN];
  if (!tbGetEKM(connection->ssl, ekm)) {
    printf("Unable to get EKM from TLS connection\n");
    exit(1);
  }
  uint8_t* data;
  size_t data_len;
  tbGetDataToSign(ekm, tbGetKeyType(tokbind_id, tokbind_id_len), false, &data,
                  &data_len);
  uint8_t* signature;
  size_t signature_len;
  signMessage(oracle, etld_plus1, data, data_len, &signature, &signature_len);
  free(data);
  uint8_t* message;
  size_t message_len;
  if (!tbBuildTokenBindingMessage(tokbind_id, tokbind_id_len, signature,
                                  signature_len, &message, &message_len)) {
    printf("Failed to build token binding message\n");
    exit(1);
  }
  free(tokbind_id);
  if (referred_tokbind_id != NULL) {
    free(referred_tokbind_id);
  }
  free(signature);
  size_t buf_len = CalculateBase64EscapedLen(message_len, false);
  char* buf = checkedCalloc(buf_len, sizeof(char));
  size_t len =
      WebSafeBase64Escape((char*)message, message_len, buf, buf_len, false);
  free(message);
  char* prefix = "Sec-Token-Binding: ";
  size_t tbheader_len = strlen(prefix) + len + 1;
  char* tbheader = checkedCalloc(tbheader_len, sizeof(char));
  strcpy(tbheader, prefix);
  strcat(tbheader, buf);
  return tbheader;
}

/* This function assumes the entire request is sent in one packet flight, and
   not split across SSL_read calls.  Also, the maximum request size is limited
   to kBufferSize. */
char* readResponse(Connection* connection) {
  char buffer[kBufferSize];
  int num_bytes = SSL_read(connection->ssl, buffer, kBufferSize);
  if (num_bytes <= 0) {
    printf("Could not read with return val %u\n", num_bytes);
    return NULL;
  }
  return copystring(buffer);
}

char* sendGetRequest(Connection* connection, char* hostname, int port,
                     char* path, char* tbheader, char* cookies) {
  char request[kBufferSize];
  size_t request_len = snprintf(request, kBufferSize,
                               "GET %s HTTP/1.0\r\n"
                               "Host: %s:%u\r\n"
                               "From: tokbind_test@example.com\r\n"
                               "User-Agent: token_bind/example/client\r\n"
                               "%s\r\n"
                               "%s\r\n",
                               path, hostname, port, tbheader, cookies);
  printf("Sending:\n%s\n", request);
  if (SSL_write(connection->ssl, request, request_len) <= 0) {
    printf("Unable to write to SSL connection\n");
    exit(1);
  }
  return readResponse(connection);
}

char* sendPostRequest(Connection* connection, char* hostname, int port,
                      char* path, char* tbheader, char* variables,
                      char* cookies) {
  char request[kBufferSize];
  size_t request_len =
      snprintf(request, kBufferSize,
               "POST %s HTTP/1.0\r\n"
               "Host: %s:%u\r\n"
               "From: tokbind_test@example.com\r\n"
               "User-Agent: token_bind/example/client\r\n"
               "%s\r\n"
               "%s\r\n"
               "%s\r\n",
               path, hostname, port, tbheader, cookies, variables);
  printf("Sending:\n%s\n", request);
  if (SSL_write(connection->ssl, request, request_len) <= 0) {
    printf("Unable to write to SSL connection\n");
    exit(1);
  }
  return readResponse(connection);
}

void closeConnection(Connection* connection) {
  printf("closing connection\n");
  SSL_shutdown(connection->ssl);
  SSL_free(connection->ssl);
  close(connection->server_fd);
  free(connection);
}

bool readKey(FILE* file, char* etld_plus1, char* key_type_name,
             char* encoded_key) {
  /* Note: fscanf is unsafe and can cause buffer overflow.  It is used for
     simplicity in this demo. */
  if (fscanf(file, "%s %s %s\n", etld_plus1, key_type_name, encoded_key) == 3) {
    return true;
  }
  return false;
}

tbKeyType getKeyTypeFromName(char* key_type_name) {
  tbKeyType i;
  for (i = 0; i < TB_INVALID_KEY_TYPE; i++) {
    if (!strcmp(tbGetKeyTypeName(i), key_type_name)) {
      return i;
    }
  }
  return TB_INVALID_KEY_TYPE;
}

void saveOracleKeys(Oracle* oracle) {
  FILE* file = fopen("key_vault", "w");
  if (file == NULL) {
    printf("Could not open key_vault for writing\n");
    exit(1);
  }
  /* The format for each key, one per line, is:
     etld+1 key_type_name base64Encoded(openssl_formatted_key_pair) */
  Key* key;
  for (key = oracle->first_key; key != NULL; key = key->next_key) {
    fprintf(file, "%s %s %s\n", key->etld_plus1,
            tbGetKeyTypeName(key->key_type), key->encoded_key);
  }
  fclose(file);
}

Cookie* findCookie(CookieJar* cookie_jar, char* hostname, char* name) {
  Cookie* cookie;
  for (cookie = cookie_jar->first_cookie; cookie != NULL;
       cookie = cookie->next_cookie) {
    if (!strcasecmp(cookie->hostname, hostname) &&
        !strcasecmp(cookie->name, name)) {
      return cookie;
    }
  }
  return NULL;
}

Cookie* createCookie(CookieJar* cookie_jar, char* hostname, char* name,
                     char* value) {
  Cookie* cookie = findCookie(cookie_jar, hostname, name);
  if (cookie != NULL) {
    free(cookie->value);
    cookie->value = copystring(value);
    return cookie;
  }
  cookie = checkedCalloc(1, sizeof(Cookie));
  cookie->hostname = copystring(hostname);
  cookie->name = copystring(name);
  cookie->value = copystring(value);
  cookie->next_cookie = cookie_jar->first_cookie;
  cookie_jar->first_cookie = cookie;
  return cookie;
}

bool readCookie(FILE* file, char* hostname, char* name, char* value) {
  /* Note: fscanf is unsafe and can cause buffer overflow.  It is used for
     simplicity in this demo. */
  if (fscanf(file, "%s %s %s\n", hostname, name, value) == 3) {
    return true;
  }
  return false;
}

/* The oracle models a secure vault for token binding keys.  Ideally, it is
   hardware backed, for example in Android TEE, or Intel SGX, but on systems
   where there is no fast signing oracle, it might be a library run in a
   different sandbox.  The important thing is to keep the private key
   inaccessible to apps and instead provide signing through an oracle.

   This function loads saved keys from a file named key_vault, to emulate a
   real hardware-backed or sandboxed signing oracle. */
Oracle* readOracleKeys(void) {
  Oracle* oracle = checkedCalloc(1, sizeof(Oracle));
  FILE* file = fopen("key_vault", "r");
  if (file == NULL) {
    /* No keys to read yet. */
    return oracle;
  }
  /* The format for each key, one per line, is:
     etld+1 key_type_name base64Encoded(openssl_formatted_key_pair) */
  char etld_plus1[kBufferSize];
  char key_type_name[kBufferSize];
  char encoded_key[kBufferSize];
  while (readKey(file, etld_plus1, key_type_name, encoded_key)) {
    tbKeyType key_type = getKeyTypeFromName(key_type_name);
    createKey(oracle, etld_plus1, key_type, encoded_key);
  }
  fclose(file);
  return oracle;
}

CookieJar* readCookieJar(void) {
  CookieJar* cookie_jar = checkedCalloc(1, sizeof(CookieJar));
  FILE* file = fopen("cookie_jar", "r");
  if (file == NULL) {
    /* No cookies to read yet. */
    return cookie_jar;
  }
  /* The format for a cookie in the jar is hostname name value. */
  char hostname[kBufferSize];
  char name[kBufferSize];
  char value[kBufferSize];
  while (readCookie(file, hostname, name, value)) {
    createCookie(cookie_jar, hostname, name, value);
  }
  fclose(file);
  return cookie_jar;
}

void saveCookieJar(CookieJar* cookie_jar) {
  FILE* file = fopen("cookie_jar", "w");
  if (file == NULL) {
    printf("Could not open cookie_jar for writing\n");
    exit(1);
  }
  /* The format for a cookie in the jar is hostname name value. */
  Cookie* cookie;
  for (cookie = cookie_jar->first_cookie; cookie != NULL;
       cookie = cookie->next_cookie) {
    fprintf(file, "%s %s %s\n", cookie->hostname, cookie->name, cookie->value);
  }
  fclose(file);
}

char* addCookie(char* p, Cookie* cookie) {
  /* Note: sprintf as used here is unsafe, and can result in buffer overflow.
     It is used for simplicity in this demo. */
  return p + sprintf(p, "Cookie: %s=%s\r\n", cookie->name, cookie->value);
}

char* findCookies(CookieJar* cookie_jar, char* hostname) {
  char cookies[kBufferSize];
  char* p = cookies;
  Cookie* cookie;
  for (cookie = cookie_jar->first_cookie; cookie != NULL;
       cookie = cookie->next_cookie) {
    if (!strcasecmp(cookie->hostname, hostname)) {
      p = addCookie(p, cookie);
    }
  }
  return copystring(cookies);
}

void processSetCookies(CookieJar* cookie_jar, char* response, char* hostname) {
  char* header_end = strstr(response, "\r\n\r\n");
  char* p = strcasestr(response, "cookie");
  while (p != NULL && (header_end == NULL || p < header_end)) {
    p += strlen("cookie");
    while (*p == ':' || *p == ' ' || *p == '\t') {
      p++;
    }
    char* name_start = p;
    char* name_end = strchr(p, '=');
    char name[kBufferSize];
    memcpy(name, name_start, name_end - name_start);
    name[name_end - name_start] = '\0';
    p = name_end + 1;
    char* value_start = p;
    while (*p != '\n' && *p != '\r' && *p != '\0') {
      p++;
    }
    char* value_end = p;
    char value[kBufferSize];
    memcpy(value, value_start, value_end - value_start);
    value[value_end - value_start] = '\0';
    createCookie(cookie_jar, hostname, name, value);
    p = strcasestr(p, "cookie");
  }
}

/* This client example sends */
int main(int argc, char** argv) {
  if (argc < 3) {
    usage();
  }
  HttpRequestType type = parseType(argv[1]);
  if (type == HTTP_UNKNOWN) {
    usage();
  }
  char* hostname;
  char* path;
  int port;
  parseHostPathAndPort(argv[2], &hostname, &path, &port);
  Connection* connection = openConnection(hostname, port);
  if (connection == NULL) {
    printf("Could not connect to %s:%u\n", hostname, port);
    return 1;
  }
  if (connection->key_type == TB_INVALID_KEY_TYPE) {
    printf("The server did not negotiate token binding\n");
    return 1;
  }
  char* etld_plus1 = getETLDPlus1(hostname);
  printf("eTLD+1=%s\n", etld_plus1);
  Oracle* oracle = readOracleKeys();
  CookieJar* cookie_jar = readCookieJar();
  char* tbheader =
      generateTokenBindingHeader(connection, oracle, etld_plus1, NULL);
  char* cookies = findCookies(cookie_jar, hostname);
  char* response;
  if (type == HTTP_GET) {
    response =
        sendGetRequest(connection, hostname, port, path, tbheader, cookies);
  } else {
    if (argc < 4) {
      usage();
    }
    char* variables = argv[3];
    response = sendPostRequest(connection, hostname, port, path, tbheader,
                               variables, cookies);
  }
  printf("Got response:\n%s\n", response);
  processSetCookies(cookie_jar, response, hostname);
  saveCookieJar(cookie_jar);
  saveOracleKeys(oracle);
  closeConnection(connection);
  return 0;
}
