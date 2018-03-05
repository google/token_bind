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

#include "token_bind_common.h"

#include <openssl/mem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <string.h>
#include "tb_bytestring.h"

static const size_t kCoordSize = 32;

/* IANA-assigned Token Binding TLS extension number */
static const int kTOKEN_BIND_EXTENSION_TYPE = 24;

/* kHeaderSize is the number of bytes on the wire for this extension
   that preceed the list of key types.  It is 3 bytes long.  The first two
   encode the protocol version, and the third is the number of key types. */
static const size_t kHeaderSize = 3;
static const size_t kMajorVersionPos = 0;  /* Major version position */
static const size_t kMinorVersionPos = 1;  /* Minor version position */
static const size_t kLengthPos = 2;        /* Length field position */

static const size_t kECDSAP256RawKeyLen = 64;
static const size_t kECDSAP256DerKeyLen = 65;
static const size_t kECDSAP256TokenBindKeyLen = 68;
static const uint8_t kUncompressedPoint = 4;

/* client_major_version and client_minor_version are global variables used
   for testing version negotiation. */
int client_major_version = TB_MAJOR_VERSION;
int client_minor_version = TB_MINOR_VERSION;

/* The following globals are initialized when first used.  They are needed to
   attach data to SSL objects. */

/* ssl_ctx_ex_data_index_key_types is used to save the preferred key types on
   the SSL context. */
static int ssl_ctx_ex_data_index_key_types = -1;
/* ssl_ex_data_index_negotiated_key_type is used to save the negotiated key type
   on an SSL connection. */
static int ssl_ex_data_index_negotiated_key_type = -1;
/* ssl_ex_data_index_negotiated_version is used to record the negotiated token
   binding version. */
static int ssl_ex_data_index_negotiated_version = -1;

struct tbKeyTypeVect_st {
  uint8_t* key_types;
  uint8_t num_key_types;
};

typedef struct tbKeyTypeVect_st tbKeyTypeVect;

/* Destroy a key type vector. */
static void tbKeyTypeVectDestroy(tbKeyTypeVect* key_type_vect) {
  if (key_type_vect == NULL) {
    return;
  }
  if (key_type_vect->key_types != NULL) {
    free(key_type_vect->key_types);
  }
  free(key_type_vect);
}

/* Create a key type vector. */
static tbKeyTypeVect* tbKeyTypeVectCreate(const uint8_t* key_types,
                                          size_t num_key_types) {
  tbKeyTypeVect* key_type_vect = calloc(1, sizeof(tbKeyTypeVect));
  if (key_type_vect == NULL) {
    return NULL;
  }
  if (num_key_types != 0) {
    key_type_vect->key_types = calloc(num_key_types, sizeof(uint8_t));
    if (key_type_vect->key_types == NULL) {
      tbKeyTypeVectDestroy(key_type_vect);
      return NULL;
    }
    key_type_vect->num_key_types = num_key_types;
    memcpy(key_type_vect->key_types, key_types,
           num_key_types * sizeof(uint8_t));
  }
  return key_type_vect;
}

/* Return true if the key type is in key_type_vect. */
static bool tbKeyTypeVectHasKeyType(const tbKeyTypeVect* key_type_vect,
                                    tbKeyType key_type) {
  return strchr((char*)(key_type_vect->key_types), key_type) != NULL;
}

/* Callback for cleaning up the tbKeyTypeVect we store on the SSL_CTX. */
static void freeKeyTypeVect(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
                            int idx, long argl, void* argp) {
  (void)parent;
  (void)ad;
  (void)idx;
  (void)argl;
  (void)argp;
  tbKeyTypeVectDestroy((tbKeyTypeVect*)ptr);
}

/* Initialize SSL extended data indexes. */
bool tbTLSLibInit(void) {
  if (ssl_ctx_ex_data_index_key_types == -1) {
    ssl_ctx_ex_data_index_key_types = SSL_CTX_get_ex_new_index(
        0 /* opaque argument for callbacks */,
        NULL /* opaque argument for callbacks */,
        NULL /* no CRYPTO_EX_new callback */,
        NULL /* no CRYPTO_EX_DUP callback */, freeKeyTypeVect);
    if (ssl_ctx_ex_data_index_key_types < 0) {
      return false;
    }
  }
  if (ssl_ex_data_index_negotiated_key_type == -1) {
    ssl_ex_data_index_negotiated_key_type =
        SSL_get_ex_new_index(0 /* opaque argument for callbacks */,
                             NULL /* opaque argument for callbacks */,
                             NULL /* no CRYPTO_EX_new callback */,
                             NULL /* no CRYPTO_EX_dup callback */,
                             NULL /* no CRYPTO_EX_free callback */);
    if (ssl_ex_data_index_negotiated_key_type < 0) {
      return false;
    }
  }
  if (ssl_ex_data_index_negotiated_version == -1) {
    ssl_ex_data_index_negotiated_version =
        SSL_get_ex_new_index(0 /* opaque argument for callbacks */,
                             NULL /* opaque argument for callbacks */,
                             NULL /* no CRYPTO_EX_new callback */,
                             NULL /* no CRYPTO_EX_dup callback */,
                             NULL /* no CRYPTO_EX_free callback */);
    if (ssl_ex_data_index_negotiated_version < 0) {
      return false;
    }
  }
  return true;
}

/* GetContextKeyTypes retrieves the key types from the context.  The context
   retains ownership of the key types vector. */
static tbKeyTypeVect* getContextKeyTypes(const SSL_CTX* ssl_ctx) {
  return SSL_CTX_get_ex_data(ssl_ctx, ssl_ctx_ex_data_index_key_types);
}

/* setContextKeyTypes set the acceptable key types on the context.  The context
   creates its own copy of the key types. */
static void setContextKeyTypes(SSL_CTX* ssl_ctx, const uint8_t* key_types,
                               size_t num_key_types) {
  tbKeyTypeVect* prev_key_types = getContextKeyTypes(ssl_ctx);
  if (prev_key_types != NULL) {
    tbKeyTypeVectDestroy(prev_key_types);
  }
  tbKeyTypeVect* key_types_vect = tbKeyTypeVectCreate(key_types, num_key_types);
  SSL_CTX_set_ex_data(ssl_ctx, ssl_ctx_ex_data_index_key_types, key_types_vect);
}

/* setNegotiatedKeyTypes sets the negotiated key types on |ssl|.  The key types
   vector must remain valid for the entire life of |ssl_ctx|. */
static void setNegotiatedKeyType(SSL* ssl, tbKeyType key_type) {
  /* Add 1 to key_type so that the default of 0 will indicate that token
     binding was not negotiatted. */
  SSL_set_ex_data(ssl, ssl_ex_data_index_negotiated_key_type,
                  (void*)(uintptr_t)(key_type + 1));
}

/* getNegotiatedKeyType retrieves the key types from the context.  The key types
   vector is owned by the caller of SetContextKeyTypes.  If token binding has
   not been negotiated, this will return TB_INVALID_KEY_TYPE. */
static tbKeyType getNegotiatedKeyType(const SSL* ssl) {
  void* ptrval = SSL_get_ex_data(ssl, ssl_ex_data_index_negotiated_key_type);
  intptr_t intval = (intptr_t)ptrval;
  if (intval == 0) {
    return TB_INVALID_KEY_TYPE;
  }
  return intval - 1;
}

/* SetNegotiatedVersion sets the negotiated extension major and minor version on
   |ssl|. */
static void setNegotiatedVersion(SSL* ssl, uint8_t major_version,
                                 uint8_t minor_version) {
  void* version = (void*)(uintptr_t)(major_version | (minor_version << 8));
  SSL_set_ex_data(ssl, ssl_ex_data_index_negotiated_version, version);
}

/* getNegotiatedVersion retrieves the negotiated major and minor version from
   |ssl|.  The major version number is written to out[0], and and the minor
   version number is written to out[1]. */
static void getNegotiatedVersion(SSL* ssl, uint8_t* out) {
  uintptr_t version =
      (uintptr_t)SSL_get_ex_data(ssl, ssl_ex_data_index_negotiated_version);
  out[0] = version;
  out[1] = version >> 8;
}

/* extensionAddServerCallback is called from BoringSSL to add the token binding
   extension to the TLS server hello packet. */
static int extensionAddServerCallback(SSL* ssl, unsigned ext_type,
                                      const uint8_t** out, size_t* out_len,
                                      int* al, void* arg) {
  (void)ext_type;
  (void)al;
  (void)arg;
  tbKeyType key_type = getNegotiatedKeyType(ssl);
  if (key_type >= TB_INVALID_KEY_TYPE) {
    /* Failed to negotiate a key type, so do not add the extension. */
    return 0;
  }
  /* Add only the negotiated key type. */
  *out_len = kHeaderSize + 1;
  uint8_t* buf = calloc(*out_len, sizeof(uint8_t));
  if (buf == NULL) {
    return 0;
  }
  /* Sets the first two bytes to the major and minor version numbers. */
  getNegotiatedVersion(ssl, buf);
  /* The number of keys sent by the server is always 1. */
  buf[kLengthPos] = 1;
  buf[kHeaderSize] = key_type;
  *out = buf;
  return 1;
}

/* extensionAddClientCallback is called from BoringSSL to add the token binding
   extension to the TLS client hello packet. */
static int extensionAddClientCallback(SSL* ssl, unsigned ext_type,
                                      const uint8_t** out, size_t* out_len,
                                      int* al, void* arg) {
  (void)ext_type;
  (void)al;
  (void)arg;
  const tbKeyTypeVect* key_type_vect = getContextKeyTypes(SSL_get_SSL_CTX(ssl));
  size_t num_key_types = key_type_vect->num_key_types;
  if (key_type_vect == NULL || num_key_types == 0 ||
      num_key_types >= TB_INVALID_KEY_TYPE) {
    return 0;
  }
  *out_len = kHeaderSize + num_key_types;
  uint8_t* buf = calloc(*out_len, sizeof(uint8_t));
  if (buf == NULL) {
    return 0;
  }
  /* Sets the first two bytes to the major and minor version numbers. */
  setNegotiatedVersion(ssl, client_major_version, client_minor_version);
  /* Copy version to buf. */
  getNegotiatedVersion(ssl, buf);
  /* Add key types from the context. */
  buf[kLengthPos] = num_key_types;
  size_t i;
  for (i = 0; i < num_key_types; i++) {
    tbKeyType key_type = key_type_vect->key_types[i];
    if (key_type >= TB_INVALID_KEY_TYPE) {
      free(buf);
      return 0;
    }
    buf[kHeaderSize + i] = key_type;
  }
  *out = buf;
  return 1;
}

/* Find the most acceptable common key type to the server. */
static tbKeyType findCommonKeyType(const SSL* ssl, const uint8_t* keys,
                                   size_t num_keys) {
  const tbKeyTypeVect* key_type_vect = getContextKeyTypes(SSL_get_SSL_CTX(ssl));
  int i;
  for (i = 0; i < key_type_vect->num_key_types; i++) {
    tbKeyType key_type = key_type_vect->key_types[i];
    if (key_type < TB_INVALID_KEY_TYPE &&
        memchr(keys, key_type, num_keys) != NULL) {
      return key_type;
    }
  }
  return TB_INVALID_KEY_TYPE;
}

/* findMutalVersion chooses a mutual version. */
static bool findMutualVersion(const unsigned char* in, uint8_t version[2]) {
  version[0] = TB_MAJOR_VERSION;
  version[1] = TB_MINOR_VERSION;
  if (in[kMajorVersionPos] < version[kMajorVersionPos] ||
      (in[kMajorVersionPos] == version[kMajorVersionPos] &&
       in[kMinorVersionPos] < version[kMinorVersionPos])) {
    /* There are experimental versions of token binding support that use old
       formats, so require a version recent enough to be compliant with the
       current token binding spec. */
    /* TODO(waywardgeek): When the min supported major version is > 0, comment
       this back in. */
    if (/* in[kMajorVersionPos] < TB_MIN_SUPPORTED_MAJOR_VERSION || */
        (in[kMajorVersionPos] == TB_MIN_SUPPORTED_MAJOR_VERSION &&
         in[kMinorVersionPos] < TB_MIN_SUPPORTED_MINOR_VERSION)) {
      /* Refuse extension if version is below minSupportedVersion */
      return false;
    }
    /* Downgrade to their supported version. */
    version[kMajorVersionPos] = in[kMajorVersionPos];
    version[kMinorVersionPos] = in[kMinorVersionPos];
  }
  return true;
}

/* extensionParseServerCallback is called from BoringSSL to parse the token
   binding extension from the TLS hello packet. */
static int extensionParseServerCallback(SSL* ssl, unsigned ext_type,
                                        const unsigned char* in, size_t in_len,
                                        int* al, void* arg) {
  (void)ext_type;
  (void)arg;
  /* Verify the length field is valid. */
  if (in_len < kHeaderSize || in[kLengthPos] + kHeaderSize != in_len) {
    *al = SSL3_AD_HANDSHAKE_FAILURE;
    return 0;  /* Invalid format - this will terminate the connection. */
  }
  uint8_t version[2];
  if (!findMutualVersion(in, version)) {
    return 1;
  }
  setNegotiatedVersion(ssl, version[0], version[1]);
  /* Find the most acceptable supported key type. */
  tbKeyType key_type =
      findCommonKeyType(ssl, in + kHeaderSize, in_len - kHeaderSize);
  /* If there were no common key types, disable Token Binding by not setting a
     negotiated key type on the SSL connection. */
  if (key_type == TB_INVALID_KEY_TYPE) {
    return 1;
  }
  setNegotiatedKeyType(ssl, key_type);
  return 1;
}

/* extensionParseClientCallback is called from BoringSSL to parse the token
   binding extension from the TLS hello packet. */
static int extensionParseClientCallback(SSL* ssl, unsigned ext_type,
                                        const unsigned char* in, size_t in_len,
                                        int* al, void* arg) {
  (void)ext_type;
  (void)arg;
  /* Verify the length field is valid. */
  if (in_len < kHeaderSize || in[kLengthPos] + kHeaderSize != in_len) {
    *al = SSL3_AD_HANDSHAKE_FAILURE;
    return 0;  /* Invalid format - this will terminate the connection. */
  }
  uint8_t version[2];
  if (!findMutualVersion(in, version)) {
    return 1;
  }
  setNegotiatedVersion(ssl, version[0], version[1]);
  /* Abort if the server sent other than exactly one key type, or a version
     higher than ours. */
  if (in_len != kHeaderSize + 1 ||
      in[kMajorVersionPos] > version[kMajorVersionPos] ||
      (in[kMajorVersionPos] == version[kMajorVersionPos] &&
       in[kMinorVersionPos] > version[kMinorVersionPos])) {
    *al = SSL3_AD_HANDSHAKE_FAILURE;
    return 0;
  }
  tbKeyType key_type = in[kHeaderSize];
  /* Abort if the server sent an unacceptable key type. */
  const tbKeyTypeVect* key_type_vect = getContextKeyTypes(SSL_get_SSL_CTX(ssl));
  if (!tbKeyTypeVectHasKeyType(key_type_vect, key_type)) {
    *al = SSL3_AD_HANDSHAKE_FAILURE;
    return 0;
  }
  /* Server key type is acceptable. */
  setNegotiatedKeyType(ssl, key_type);
  return 1;
}

static void freeTLSOutData(SSL* ssl, unsigned extension_value,
                           const uint8_t* out, void* add_arg) {
  (void)ssl;
  (void)extension_value;
  (void)add_arg;
  free((uint8_t*)out);
}

/* DER formatted integers can be negative, so when encoding a positive integer
   that starts with a 1 in the MSB of the most significant byte, a leading 0
   byte is added.  To extract an unsigned int, we need to strip off any leading
   0.  |out_buf| is buf_len in size, so we fill the initial bytes with 0's if
   the DER encoded integer does not use all the bytes in the buffer. */
static bool getDerUint(tbCBS* uint_cbs, uint8_t* out_buf, size_t buf_len) {
  const uint8_t* data = tbCBS_data(uint_cbs);
  size_t length = tbCBS_len(uint_cbs);
  if (length == 0) {
    return false;
  }
  if (data[0] == 0) {
    data++;
    length--;
  }
  if (length > buf_len) {
    return false;
  }
  if (buf_len > length) {
    /* 0-pad the buffer. */
    memset(out_buf, 0, buf_len - length);
  }
  memcpy(out_buf + (buf_len - length), data, length);
  return true;
}

/* Similarly, to encode an unsigned int, we need to add a leading 0 if the MSB
   is 1, and if we have leading 0-bytes, we strip them unless the next byte MSB
   is set, or if the only byte left is a 0. */
static bool addDerUint(tbCBB* uint_cbb, const uint8_t* in_buf, size_t length) {
  if (length == 0) {
    return false;
  }
  size_t pos = 0;
  /* Strip leading 0's except for the last byte. */
  while (pos + 1 < length && in_buf[pos] == 0) {
    pos++;
  }
  if ((in_buf[pos] & 0x80) != 0) {
    tbCBB_add_u8(uint_cbb, 0);
  }
  return tbCBB_add_bytes(uint_cbb, in_buf + pos, length - pos);
}

void tbSetClientVersion(int major_version, int minor_version) {
  client_major_version = major_version;
  client_minor_version = minor_version;
}

bool tbEnableTLSTokenBindingNegotiation(SSL_CTX* ssl_ctx) {
  uint8_t key_types[] = {TB_ECDSAP256, TB_RSA2048_PSS, TB_RSA2048_PKCS15};
  setContextKeyTypes(ssl_ctx, key_types, sizeof(key_types));
  if (SSL_CTX_add_server_custom_ext(
          ssl_ctx, kTOKEN_BIND_EXTENSION_TYPE, &extensionAddServerCallback,
          freeTLSOutData, NULL, &extensionParseServerCallback, NULL) != 1) {
    return false;
  }
  if (SSL_CTX_add_client_custom_ext(
          ssl_ctx, kTOKEN_BIND_EXTENSION_TYPE, &extensionAddClientCallback,
          freeTLSOutData, NULL, &extensionParseClientCallback, NULL) != 1) {
    return false;
  }
  return true;
}

void tbUpdateKeyTypes(SSL_CTX* ssl_ctx, const uint8_t* key_types,
                      size_t num_key_types) {
  setContextKeyTypes(ssl_ctx, key_types, num_key_types);
}

bool tbTokenBindingEnabled(const SSL* ssl, tbKeyType* out_key_type) {
  if (SSL_get_extms_support((SSL*)ssl) != 1) {
    return false;
  }
  tbKeyType key_type = getNegotiatedKeyType(ssl);
  if (key_type == TB_INVALID_KEY_TYPE) {
    return false;
  }
  if (out_key_type != NULL) {
    *out_key_type = key_type;
  }
  return true;
}

const char* tbGetKeyTypeName(tbKeyType key_type) {
  switch (key_type) {
    case TB_RSA2048_PKCS15: return "RSA-2048-PKCS1.5";
    case TB_RSA2048_PSS: return "RSA-2048-PSS";
    case TB_ECDSAP256: return "EC-DSA-P256";
    case TB_INVALID_KEY_TYPE: return "invalid-key-type";
  }
  return "unknown-key-type";
}

tbKeyType tbGetKeyType(const uint8_t* tokbind_id, size_t tokbind_id_len) {
  if (tokbind_id_len == 0) {
    return TB_INVALID_KEY_TYPE;
  }
  return tokbind_id[0];
}

bool tbGetEKM(const SSL* ssl, uint8_t out[TB_HASH_LEN]) {
  if (ssl == NULL) {
    return false;
  }
  static const char kLabel[] = "EXPORTER-Token-Binding";
  return SSL_export_keying_material((SSL*)ssl, out, TB_HASH_LEN, kLabel,
                                    strlen(kLabel), NULL, 0, 0);
}

void tbGetDataToSign(uint8_t* ekm, tbKeyType key_type, bool referred,
                     uint8_t** out_data, size_t* out_data_len) {
  *out_data_len = SHA256_DIGEST_LENGTH + 2;
  *out_data = calloc(*out_data_len, sizeof(uint8_t));
  (*out_data)[0] = referred ? TB_REFERRED : TB_PROVIDED;
  (*out_data)[1] = key_type;
  memcpy(*out_data + 2, ekm, SHA256_DIGEST_LENGTH);
}

bool tbSetPadding(tbKeyType key_type, EVP_PKEY_CTX* key_ctx) {
  switch (key_type) {
    case TB_RSA2048_PKCS15:
      return EVP_PKEY_CTX_set_rsa_padding(key_ctx, RSA_PKCS1_PADDING);
    case TB_RSA2048_PSS:
      if (!EVP_PKEY_CTX_set_rsa_padding(key_ctx, RSA_PKCS1_PSS_PADDING)) {
        return false;
      }
      /* Set salt length to the digest length. */
      return EVP_PKEY_CTX_set_rsa_pss_saltlen(key_ctx, -1) == 1;
    case TB_ECDSAP256:
      return true;
    default:
      return false;
  }
}

/* The "DER" format for keys is really just a format convention created by
   programmers over the years as they added support for new key types to OpenSSL
   and other libraries.  The "DER" format for RSA keys is:

       SEQUENCE INTEGER(modulus) INTEGER(exponent)

   which is an actual DER encoding.  For ECC keys, it is:

       1-byte 0x4. 32-byte X, 32-byte Y

   which is a non-DER custom format.  Token Binding uses custom formats.  For
   RSA keys, it is:

       u8-key_type, u16-prefixed(u16-prefixed(modulus), u8-prefixed(exponent))

   and for ECC keys:

       u8-key_type, u16-prefixed(u8-prefixed(32-byte X || 32-byt Y)) */
bool tbConvertDerKeyToTokenBindingID(const uint8_t* der_key, size_t der_key_len,
                                     tbKeyType key_type,
                                     uint8_t** out_tokbind_id,
                                     size_t* out_tokbind_id_len) {
  switch (key_type) {
    case TB_ECDSAP256: {
      if (der_key_len != kECDSAP256RawKeyLen + 1 ||
          der_key[0] != kUncompressedPoint) {
        return false;
      }
      tbCBB tokbind_id, ec_point, raw_key;
      if (!tbCBB_init(&tokbind_id, kECDSAP256TokenBindKeyLen) ||
          !tbCBB_add_u8(&tokbind_id, TB_ECDSAP256) ||
          !tbCBB_add_u16_length_prefixed(&tokbind_id, &ec_point) ||
          !tbCBB_add_u8_length_prefixed(&ec_point, &raw_key) ||
          !tbCBB_add_bytes(&raw_key, der_key + 1, der_key_len - 1) ||
          !tbCBB_finish(&tokbind_id, out_tokbind_id, out_tokbind_id_len)) {
        tbCBB_cleanup(&tokbind_id);
        return false;
      }
      return true;
    }
    case TB_RSA2048_PKCS15:
    case TB_RSA2048_PSS: {
      tbCBS key_cbs;
      tbCBS_init(&key_cbs, der_key, der_key_len);
      tbCBS sequence_cbs, modulus_cbs, exponent_cbs;
      if (!tbCBS_get_asn1(&key_cbs, &sequence_cbs, tbCBS_ASN1_SEQUENCE) ||
          tbCBS_len(&key_cbs) != 0 ||
          !tbCBS_get_asn1(&sequence_cbs, &modulus_cbs, tbCBS_ASN1_INTEGER) ||
          !tbCBS_get_asn1(&sequence_cbs, &exponent_cbs, tbCBS_ASN1_INTEGER) ||
          tbCBS_len(&sequence_cbs) != 0) {
        return false;
      }
      /* Skip any leading 0 on modulus and exponent.  These are added in DER
         format when the MSB of an unsigned integer is 1. */
      uint8_t val;
      while (tbCBS_data(&modulus_cbs)[0] == 0) {
        tbCBS_get_u8(&modulus_cbs, &val);
      }
      while (tbCBS_data(&exponent_cbs)[0] == 0) {
        tbCBS_get_u8(&exponent_cbs, &val);
      }
      tbCBB tokbind_id_cbb, key_content_cbb, modulus_cbb, exponent_cbb;
      if (!tbCBB_init(&tokbind_id_cbb, 0) ||
          !tbCBB_add_u8(&tokbind_id_cbb, key_type) ||
          !tbCBB_add_u16_length_prefixed(&tokbind_id_cbb, &key_content_cbb) ||
          !tbCBB_add_u16_length_prefixed(&key_content_cbb, &modulus_cbb) ||
          !tbCBB_add_bytes(&modulus_cbb, tbCBS_data(&modulus_cbs),
                           tbCBS_len(&modulus_cbs)) ||
          !tbCBB_add_u8_length_prefixed(&key_content_cbb, &exponent_cbb) ||
          !tbCBB_add_bytes(&exponent_cbb, tbCBS_data(&exponent_cbs),
                           tbCBS_len(&exponent_cbs)) ||
          !tbCBB_finish(&tokbind_id_cbb, out_tokbind_id, out_tokbind_id_len)) {
        tbCBB_cleanup(&tokbind_id_cbb);
        return false;
      }
      return true;
    }
    case TB_INVALID_KEY_TYPE:
      break;
  }
  return false;  /* Unsupported key type. */
}

bool tbConvertTokenBindingIDToDerKey(const uint8_t* tokbind_id,
                                     size_t tokbind_id_len,
                                     tbKeyType* out_key_type, uint8_t** out_key,
                                     size_t* out_key_len) {
  *out_key = NULL;
  tbCBS tokbind_id_cbs;
  tbCBS_init(&tokbind_id_cbs, tokbind_id, tokbind_id_len);
  uint8_t key_type_val;
  if (!tbCBS_get_u8(&tokbind_id_cbs, &key_type_val)) {
    return false;
  }
  *out_key_type = key_type_val;
  tbCBS key_content_cbs;
  if (!tbCBS_get_u16_length_prefixed(&tokbind_id_cbs, &key_content_cbs) ||
      tbCBS_len(&tokbind_id_cbs) != 0) {
    return false;
  }
  switch (key_type_val) {
    case TB_ECDSAP256: {
      tbCBS raw_key;
      if (tokbind_id_len != kECDSAP256TokenBindKeyLen ||
          !tbCBS_get_u8_length_prefixed(&key_content_cbs, &raw_key) ||
          tbCBS_len(&key_content_cbs) != 0 ||
          tbCBS_len(&raw_key) != kECDSAP256RawKeyLen) {
        return false;
      }
      *out_key_len = kECDSAP256DerKeyLen;
      *out_key = calloc(*out_key_len, sizeof(uint8_t));
      if (*out_key == NULL) {
        return false;
      }
      /* Add the uncompressed point 0x4 prefix */
      (*out_key)[0] = kUncompressedPoint;
      /* Add X and Y. */
      memcpy(*out_key + 1, tbCBS_data(&raw_key), kECDSAP256RawKeyLen);
      break;
    }
    case TB_RSA2048_PKCS15:
    case TB_RSA2048_PSS: {
      tbCBS modulus_cbs, exponent_cbs;
      if (!tbCBS_get_u16_length_prefixed(&key_content_cbs, &modulus_cbs) ||
          !tbCBS_get_u8_length_prefixed(&key_content_cbs, &exponent_cbs) ||
          tbCBS_len(&key_content_cbs) != 0) {
        return false;
      }
      tbCBB key_cbb, sequence_cbb, modulus_cbb, exponent_cbb;
      tbCBB_init(&key_cbb, 0);
      if (!tbCBB_add_asn1(&key_cbb, &sequence_cbb, tbCBS_ASN1_SEQUENCE) ||
          !tbCBB_add_asn1(&sequence_cbb, &modulus_cbb, tbCBS_ASN1_INTEGER) ||
          !addDerUint(&modulus_cbb, tbCBS_data(&modulus_cbs),
                      tbCBS_len(&modulus_cbs)) ||
          !tbCBB_add_asn1(&sequence_cbb, &exponent_cbb, tbCBS_ASN1_INTEGER) ||
          !addDerUint(&exponent_cbb, tbCBS_data(&exponent_cbs),
                      tbCBS_len(&exponent_cbs)) ||
          !tbCBB_finish(&key_cbb, out_key, out_key_len)) {
        tbCBB_cleanup(&key_cbb);
        return false;
      }
      break;
    }
    default:
      return false;  /* Unsupported key type */
  }
  if (tbCBS_len(&tokbind_id_cbs) != 0) {
    if (*out_key != NULL) {
      free(*out_key);
      *out_key = NULL;
    }
    return false;
  }
  return true;
}

/* The "DER" format for signatures is really just a format convention created by
   programmers over the years as they added support for new key types to OpenSSL
   and other libraries.  The "DER" format for RSA signatures is:

       256-byte encrypted message

   which is not in DER format, unlike RSA keys.  Note that there is no length
   prefix.  ECC signatures have the form:

       SEQUENCE INTEGER(r) INTEGER(s)

   which is in DER format, unlike ECC keys.  Token Binding uses custom formats.
   For RSA keys, it is:

       256-byte encrypted message

   and for ECC keys:

       32-byte R || 32-byte-S */
bool tbConvertDerSigToTokenBindingSig(const uint8_t* der_sig,
                                      size_t der_sig_len, tbKeyType key_type,
                                      uint8_t** out_sig, size_t* out_sig_len) {
  switch (key_type) {
    case TB_ECDSAP256: {
      tbCBS sig_cbs;
      tbCBS_init(&sig_cbs, der_sig, der_sig_len);
      *out_sig_len = 2 * kCoordSize;
      *out_sig = calloc(*out_sig_len, sizeof(uint8_t));
      if (*out_sig == NULL) {
        return false;
      }
      tbCBS sequence_cbs, r_cbs, s_cbs;
      if (!tbCBS_get_asn1(&sig_cbs, &sequence_cbs, tbCBS_ASN1_SEQUENCE) ||
          tbCBS_len(&sig_cbs) != 0 ||
          !tbCBS_get_asn1(&sequence_cbs, &r_cbs, tbCBS_ASN1_INTEGER) ||
          !getDerUint(&r_cbs, *out_sig, kCoordSize) ||
          !tbCBS_get_asn1(&sequence_cbs, &s_cbs, tbCBS_ASN1_INTEGER) ||
          !getDerUint(&s_cbs, *out_sig + kCoordSize, kCoordSize) ||
          tbCBS_len(&sequence_cbs) != 0) {
        free(out_sig);
        return false;
      }
      return true;
    }
    case TB_RSA2048_PKCS15:
    case TB_RSA2048_PSS: {
      if (der_sig_len == 8) {
        return false;
      }
      *out_sig_len = der_sig_len;
      *out_sig = calloc(*out_sig_len, sizeof(uint8_t));
      if (*out_sig == NULL) {
        return false;
      }
      memcpy(*out_sig, der_sig, der_sig_len);
      return true;
    }
    default:
      return false;  /* Unsupported key type */
  }
  return false;  /* Cannot get here. */
}

bool tbConvertTokenBindingSigToDerSig(const uint8_t* tb_sig, size_t tb_sig_len,
                                      tbKeyType key_type, uint8_t** out_sig,
                                      size_t* out_sig_len) {
  switch (key_type) {
    case TB_ECDSAP256: {
      if (tb_sig_len != 2 * kCoordSize) {
        return false;  /* Invalid signature length */
      }
      tbCBB sig_cbb;
      tbCBB_init(&sig_cbb, 0);
      tbCBB sequence_cbb, r_cbb, s_cbb;
      if (!tbCBB_add_asn1(&sig_cbb, &sequence_cbb, tbCBS_ASN1_SEQUENCE) ||
          !tbCBB_add_asn1(&sequence_cbb, &r_cbb, tbCBS_ASN1_INTEGER) ||
          !addDerUint(&r_cbb, tb_sig, kCoordSize) ||
          !tbCBB_add_asn1(&sequence_cbb, &s_cbb, tbCBS_ASN1_INTEGER) ||
          !addDerUint(&s_cbb, tb_sig + kCoordSize, kCoordSize) ||
          !tbCBB_finish(&sig_cbb, out_sig, out_sig_len)) {
        tbCBB_cleanup(&sig_cbb);
        return false;
      }
      return true;
    }
    case TB_RSA2048_PKCS15:
    case TB_RSA2048_PSS: {
      if (tb_sig_len == 0) {
        return false;
      }
      *out_sig_len = tb_sig_len;
      *out_sig = OPENSSL_malloc(out_sig_len * sizeof(uint8_t));
      if (*out_sig == NULL) {
        return false;
      }
      memcpy(*out_sig, tb_sig, tb_sig_len);
      return true;
    }
    default:
      return false;  /* Unsupported key type */
  }
  return false;  /* Cannot get here. */
}

void tbHashTokenBindingID(const uint8_t* tokbind_id, size_t tokbind_id_len,
                          uint8_t hash_out[TB_HASH_LEN]) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, tokbind_id, tokbind_id_len);
  SHA256_Final(hash_out, &sha256);
}
