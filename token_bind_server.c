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

#include "token_bind_server.h"

#include <openssl/ec.h>
#include <openssl/mem.h>
#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>
#include "tb_bytestring.h"

static uint64_t tbCacheNonce = 0;

struct tbCacheStruct {
  uint64_t* message_hashes;
  uint32_t num_message_hashes;
  tbCacheStatus status;
};

tbCacheStatus tbCacheGetStatus(tbCache* cache) {
  return cache->status;
}

/* extractTokenBindingID extracts the sub-string of |message_contents| that
   represent the public key (a TokenBindingID), starting with the KeyType byte.
   If |out_evp_key| is not NULL, then an EVP_PKEY is parsed from this string,
   and |out_evp_key| is set to own it.  Note that this function will return true
   after setting |out_tokbind_id| when |out_evp_key| is NULL, even if
   out_tokbind_id does not represent a valid EVP_PKEY.  This is useful behavior
   when we have cache hits for message headers, and just need to extract the
   TokenBindingID portion, without building an EVP_PKEY.  The caller takes
   ownership of out_evp_key but not out_tokbind_id, which is a pointer into
   |message_contents|. */
static bool extractTokenBindingID(tbCBS* message_contents,
                                  tbKeyType* out_key_type,
                                  EVP_PKEY** out_evp_key,
                                  const uint8_t** out_tokbind_id,
                                  size_t* out_tokbind_id_len) {
  const uint8_t* tokbind_id_data = tbCBS_data(message_contents);
  uint8_t key_type;
  tbCBS tokbind_id_cbs;
  if (!tbCBS_get_u8(message_contents, &key_type) ||
      !tbCBS_get_u16_length_prefixed(message_contents, &tokbind_id_cbs)) {
    return false;
  }
  /* The total length includes the key type and uint16_t length field */
  size_t tokbind_id_len = tbCBS_len(&tokbind_id_cbs) + 3;
  *out_key_type = key_type;
  if (out_tokbind_id != NULL) {
    *out_tokbind_id = tokbind_id_data;
    *out_tokbind_id_len = tokbind_id_len;
  }
  if (out_evp_key == NULL) {
    return true;
  }
  uint8_t* der_key;
  size_t der_key_len;
  if (!tbConvertTokenBindingIDToDerKey(tokbind_id_data, tokbind_id_len,
                                       out_key_type, &der_key, &der_key_len)) {
    return false;
  }
  switch (*out_key_type) {
    case TB_ECDSAP256: {
      EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
      if (eckey == NULL) {
        free(der_key);
        return false;
      }
      const uint8_t* inp = der_key;
      if (o2i_ECPublicKey(&eckey, &inp, der_key_len) == NULL) {
        EC_KEY_free(eckey);
        free(der_key);
        return false;
      }
      free(der_key);
      EVP_PKEY* evp_key = EVP_PKEY_new();
      if (evp_key == NULL) {
        return false;
      }
      EVP_PKEY_assign_EC_KEY(evp_key, eckey);
      *out_evp_key = evp_key;
      return true;
    }
    case TB_RSA2048_PKCS15:
    case TB_RSA2048_PSS: {
      const size_t kModulusSize = 2048;
      const uint8_t* inp = der_key;
      RSA* rsa = d2i_RSAPublicKey(NULL, &inp, der_key_len);
      free(der_key);
      if (rsa == NULL) {
        return false;
      }
      if ((unsigned)(8 * RSA_size(rsa)) != kModulusSize) {
        RSA_free(rsa);
        return false;
      }
      EVP_PKEY* evp_key = EVP_PKEY_new();
      if (evp_key == NULL) {
        RSA_free(rsa);
        return false;
      }
      EVP_PKEY_assign_RSA(evp_key, rsa);
      *out_evp_key = evp_key;
      return true;
    }
    case TB_INVALID_KEY_TYPE:
      break;
  }
  /* Unknown key type, so we cannot parse it. */
  free(der_key);
  return false;
}

/* fastHash mixes |nonce| with |message|.  An attacker is assumed not to know
   the nonce value.  When inserting messages into the cache, messages have
   verified cryptographic signatures.  The attacker will not be able to control
   the bits in at least one 64-bit value of the message when inserting into the
   cache.  When it is mixed with the random nonce, the attacker will not be able
   to predict the resulting hash.  Four 64-bit lanes of data are hashed in
   parallel to take advantage of multiplier pipelining.  The point of fastHash
   is to enable secure 64-bit cache entries that are resistant to offline
   attacks, rather than 128-bit entries that would be required without the
   nonce.  An attacker attempting to pass the MessageAlreadyVerified check with
   a bogus message due to a collision has at most a 16 in 2^64 chance per
   on-line attempt, even if they can exactly control the resulting hash of bogus
   signatures.  The entire justification for fastHash is speed.  HMAC-SHA256 is
   ~1µs for this use case, while this function should hash at a rate close to 1
   byte/cycle, or about 40ns. */
static uint64_t fastHash(uint64_t nonce, const uint8_t* message,
                         size_t message_len) {
  uint64_t hash[4] = {nonce, nonce, nonce, nonce};
  uint64_t value[4] = {0, 0, 0, 0};
  const uint8_t* p = message;
  size_t length = message_len;
  while (length != 0) {
    if (length >= 4 * sizeof(uint64_t)) {
      memcpy(&value, p, 4 * sizeof(uint64_t));
      p += 4 * sizeof(uint64_t);
      length -= 4 * sizeof(uint64_t);
    } else {
      memcpy(&value, p, length);
      length = 0;
    }
    /* This loop will be unrolled, and the hash and value arrays assigned to
       registers for some pretty sweet speed. */
    int i;
    for (i = 0; i < 4; i++) {
      /* Note that this is reversible, meaning hash[i] does not lose entropy.
         This is a Latin square from Lyra2's BlaMka. */
      hash[i] += value[i] + 2 * hash[i] * value[i];
      /* Ensure each in bit impacts at least 33 out bits. */
      hash[i] ^= hash[i] >> 32;
    }
  }
  return hash[0] ^ hash[1] ^ hash[2] ^ hash[3];
}

tbCache* tbCacheCreate(void) {
  /* If your code is failing this check, call LibInit first. */
  if (tbCacheNonce == 0) {
    return NULL;
  }
  tbCache* cache = calloc(1, sizeof(tbCache));
  if (cache == NULL) {
    return NULL;
  }
  cache->status = TB_CACHE_OK;
  return cache;
}

void tbCacheDestroy(tbCache* cache) {
  if (cache == NULL) {
    return;
  }
  if (cache->message_hashes != NULL) {
    free(cache->message_hashes);
  }
  free(cache);
}

void tbCacheLibInit(uint64_t nonce) {
  if (tbCacheNonce != 0) {
    /* The library only needs to be initilaized once.  Changing the nonce would
       cause the cache to have garbage entries. */
    return;
  }
  if (nonce == 0) {
    nonce = 1;
  }
  tbCacheNonce = nonce;
}

/* Lookup the hash in the small array of cached hashes and return the position
   if found.  Otherwise, return -1. */
static int findHashInCache(tbCache* cache, uint64_t hash) {
  size_t i;
  for (i = 0; i < cache->num_message_hashes; i++) {
    if (cache->message_hashes[i] == hash) {
      return i;
    }
  }
  return -1;
}

/* Lookup the message in the message cache.  Return true if it is there. */
static bool cacheLookup(tbCache* cache, const uint8_t* message,
                          size_t message_len) {
  uint64_t hash = fastHash(tbCacheNonce, message, message_len);
  int pos = findHashInCache(cache, hash);
  if (pos == -1) {
    return false;
  }
  if (pos != 0) {
    /* Move hash to first position in LRU cache. */
    memmove(cache->message_hashes + 1, cache->message_hashes,
            pos * sizeof(uint64_t));
    cache->message_hashes[0] = hash;
  }
  return true;
}

/* Return true if x is a power of 2.  Note: assumes x > 0. */
static bool isPowerOfTwo(uint32_t x) {
  return !(x & (x - 1));
}

/* Add the hash of the message to the message hash cache.  This sets the error
   code to TB_WARNING_CACHE_OVERFLOW if the cache overflowed. */
static void cacheAdd(tbCache* cache, const uint8_t* message,
                       size_t message_len) {
  uint64_t hash = fastHash(tbCacheNonce, message, message_len);
  if (findHashInCache(cache, hash) != -1) {
    return;  /* Already in cache */
  }
  if (cache->num_message_hashes == 0) {
    cache->message_hashes = calloc(2, sizeof(uint64_t));
    if (cache == NULL) {
      cache->status = TB_CACHE_MEMORY_ERROR;
      return;
    }
  }
  if (cache->num_message_hashes == TB_CACHE_SIZE) {
    memmove(cache->message_hashes + 1, cache->message_hashes,
            (TB_CACHE_SIZE - 1) * sizeof(uint64_t));
    cache->status = TB_CACHE_OVERFLOW;
  } else {
    if (cache->num_message_hashes >= 2 &&
        isPowerOfTwo(cache->num_message_hashes)) {
      uint64_t* message_hashes =
          realloc(cache->message_hashes,
                  (cache->num_message_hashes << 1) * sizeof(uint64_t));
      if (message_hashes == NULL) {
        cache->status = TB_CACHE_MEMORY_ERROR;
        return;
      }
      cache->message_hashes = message_hashes;
    }
    memmove(cache->message_hashes + 1, cache->message_hashes,
            cache->num_message_hashes * sizeof(uint64_t));
    cache->num_message_hashes++;
  }
  cache->message_hashes[0] = hash;
}

bool tbCacheMessageAlreadyVerified(tbCache* cache, const uint8_t* message,
                                   size_t message_len, uint8_t** out_tokbind_id,
                                   size_t* out_tokbind_id_len,
                                   uint8_t** out_referred_tokbind_id,
                                   size_t* out_referred_tokbind_id_len) {
  if (out_tokbind_id == NULL || out_referred_tokbind_id == NULL) {
    return false;
  }
  *out_tokbind_id = NULL;
  *out_referred_tokbind_id = NULL;
  if (message_len == 0) {
    cache->status = TB_CACHE_INVALID_FORMAT;
    return false;
  }
  if (!cacheLookup(cache, message, message_len)) {
    cache->status = TB_CACHE_MISS;
    return false;
  }
  cache->status = TB_CACHE_HIT;
  tbCBS tokbind_message, message_contents;
  tbCBS_init(&tokbind_message, message, message_len);
  if (!tbCBS_get_u16_length_prefixed(&tokbind_message, &message_contents) ||
     tbCBS_len(&message_contents) + 2 != message_len) {
    cache->status = TB_CACHE_INVALID_FORMAT;
    return false;
  }
  uint8_t* tokbind_id;
  size_t tokbind_id_len;
  uint8_t tokbind_type;
  tbKeyType type;
  while (tbCBS_len(&message_contents) != 0) {
    tbCBS signature;
    tbCBS extensions;  // Currently we ignore all extensions
    if (!tbCBS_get_u8(&message_contents, &tokbind_type) ||
        !extractTokenBindingID(&message_contents, &type, NULL,
                               (const uint8_t**)&tokbind_id, &tokbind_id_len) ||
        !tbCBS_get_u16_length_prefixed(&message_contents, &signature) ||
        !tbCBS_get_u16_length_prefixed(&message_contents, &extensions)) {
      /* Should never happen, since message was already verified. */
      cache->status = TB_CACHE_INVALID_FORMAT;
      return false;
    }
    if (tokbind_type == TB_PROVIDED) {
      *out_tokbind_id = tokbind_id;
      *out_tokbind_id_len = tokbind_id_len;
    } else if (tokbind_type == TB_REFERRED) {
      *out_referred_tokbind_id = tokbind_id;
      *out_referred_tokbind_id_len = tokbind_id_len;
    } else {
      /* Should never happen, since message was already verified. */
      cache->status = TB_CACHE_INVALID_FORMAT;
      return false;
    }
  }
  return true;
}

bool tbCacheVerifyTokenBindingMessage(
    tbCache* cache, const uint8_t* message, size_t message_len,
    tbKeyType expected_key_type, const uint8_t ekm[TB_HASH_LEN],
    uint8_t** out_tokbind_id, size_t* out_tokbind_id_len,
    uint8_t** out_referred_tokbind_id, size_t* out_referred_tokbind_id_len) {
  if (message_len == 0 || out_tokbind_id == NULL ||
      out_referred_tokbind_id == NULL) {
    cache->status = TB_CACHE_INVALID_FORMAT;
    return false;
  }
  *out_tokbind_id = NULL;
  *out_referred_tokbind_id = NULL;
  tbCBS tokbind_message, message_contents, signature;
  tbCBS_init(&tokbind_message, message, message_len);
  if (!tbCBS_get_u16_length_prefixed(&tokbind_message, &message_contents) ||
      tbCBS_len(&message_contents) + 2 != message_len) {
    cache->status = TB_CACHE_INVALID_FORMAT;
    return false;
  }
  bool has_provided = false;
  bool has_referred = false;
  EVP_PKEY* evp_key = NULL;
  EVP_MD_CTX* md_ctx = NULL;
  uint8_t* dersig = NULL;
  size_t dersig_len;
  while (tbCBS_len(&message_contents) != 0) {
    uint8_t tokbind_type;
    tbKeyType key_type;
    /* Initialize variables we may need to free if an error occurs. */
    evp_key = NULL;
    md_ctx = NULL;
    dersig = NULL;
    uint8_t* tokbind_id = NULL;
    size_t tokbind_id_len = 0;
    tbCBS extensions;  // Currently we ignore all extensions
    if (!tbCBS_get_u8(&message_contents, &tokbind_type) ||
        !extractTokenBindingID(&message_contents, &key_type, &evp_key,
                               (const uint8_t**)&tokbind_id, &tokbind_id_len) ||
        !tbCBS_get_u16_length_prefixed(&message_contents, &signature) ||
        (tokbind_type == TB_PROVIDED && key_type != expected_key_type) ||
        !tbCBS_get_u16_length_prefixed(&message_contents, &extensions)) {
      cache->status = TB_CACHE_INVALID_FORMAT;
      goto err;
    }
    const uint8_t* sig_data = tbCBS_data(&signature);
    size_t sig_data_len = tbCBS_len(&signature);
    /* Signature is in  token binding format, but must be in DER format before
       passing to OpenSSL. */
    if (!tbConvertTokenBindingSigToDerSig(sig_data, sig_data_len, key_type,
                                          &dersig, &dersig_len)) {
      cache->status = TB_CACHE_INVALID_FORMAT;
      goto err;
    }
    md_ctx = EVP_MD_CTX_create();
    EVP_PKEY_CTX* key_ctx;
    uint8_t sigdata[TB_HASH_LEN + 2];
    sigdata[0] = tokbind_type;
    sigdata[1] = key_type;
    memcpy(sigdata + 2, ekm, TB_HASH_LEN);
    if (EVP_DigestVerifyInit(md_ctx, &key_ctx, EVP_sha256(), NULL, evp_key) !=
            1 ||
        !tbSetPadding(key_type, key_ctx) ||
        !EVP_DigestVerifyUpdate(md_ctx, sigdata, TB_HASH_LEN + 2) ||
        !EVP_DigestVerifyFinal(md_ctx, dersig, dersig_len)) {
      cache->status = TB_CACHE_BAD_SIGNATURE;
      goto err;
    }
    OPENSSL_free(dersig);
    dersig = NULL;
    EVP_MD_CTX_destroy(md_ctx);
    md_ctx = NULL;
    EVP_PKEY_free(evp_key);
    evp_key = NULL;
    if (tokbind_type == TB_PROVIDED) {
      if (has_provided) {
        cache->status = TB_CACHE_INVALID_FORMAT;
        goto err;
      }
      has_provided = true;
      *out_tokbind_id = tokbind_id;
      *out_tokbind_id_len = tokbind_id_len;
    } else if (tokbind_type == TB_REFERRED) {
      if (has_referred) {
        cache->status = TB_CACHE_INVALID_FORMAT;
        goto err;
      }
      has_referred = true;
      *out_referred_tokbind_id = tokbind_id;
      *out_referred_tokbind_id_len = tokbind_id_len;
    }
  }
  if (!has_provided) {
    /* A provided token binding is required. */
    cache->status = TB_CACHE_INVALID_FORMAT;
    goto err;
  }
  cache->status = TB_CACHE_GOOD_SIGNATURE;
  cacheAdd(cache, message, message_len);
  return true;
err:
  if (evp_key != NULL) {
    EVP_PKEY_free(evp_key);
  }
  if (md_ctx != NULL) {
    EVP_MD_CTX_destroy(md_ctx);
  }
  if (dersig != NULL) {
    free(dersig);
  }
  return false;
}

const char* tbCacheGetStatusString(tbCacheStatus status) {
  switch (status) {
    case TB_CACHE_OK:
      return "cache-ok";
    case TB_CACHE_BAD_SIGNATURE:
      return "bad-signature";
    case TB_CACHE_GOOD_SIGNATURE:
      return "good-signature";
    case TB_CACHE_HIT:
      return "cache-hit";
    case TB_CACHE_INVALID_FORMAT:
      return "invalid-format";
    case TB_CACHE_MEMORY_ERROR:
      return "memory-error";
    case TB_CACHE_MISS:
      return "cache-miss";
    case TB_CACHE_OVERFLOW:
      return "cache-overflow";
  }
  return NULL;
}

EVP_PKEY* tbDecodeTokenBindingID(const uint8_t* tokbind_id,
                                 size_t tokbind_id_len,
                                 tbKeyType* out_key_type) {
  tbCBS tokbind_id_cbs;
  tbCBS_init(&tokbind_id_cbs, tokbind_id, tokbind_id_len);
  EVP_PKEY* evp_key;
  uint8_t* tb_id;
  size_t tb_id_len;
  if (!extractTokenBindingID(&tokbind_id_cbs, out_key_type, &evp_key,
                             (const uint8_t**)&tb_id, &tb_id_len)) {
    return NULL;
  }
  if (tbCBS_len(&tokbind_id_cbs) != 0) {
    EVP_PKEY_free(evp_key);
    return NULL;
  }
  return evp_key;
}
