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

#ifndef TOKEN_BIND_CSRC_TOKEN_BIND_SERVER_H_
#define TOKEN_BIND_CSRC_TOKEN_BIND_SERVER_H_

/* This library implements Token Binding, as specified in:
   https://datatracker.ietf.org/doc/draft-ietf-tokbind-protocol

   In essence, Token Binding is the next version of Channel ID.  It is on track
   to become an IETF standard. */

#include <openssl/evp.h>
#include "token_bind_common.h"

/* tbCache should be allocated on a server's SSL connection when a Token Binding
   is negotiated successfully with the client.  It provides APIs for validating
   Token Binding headers, as well as keeping a small cache of previously
   validated headers, to reduce the work required per HTTP request. */
struct tbCacheStruct;
typedef struct tbCacheStruct tbCache;

#define TB_CACHE_SIZE 16

tbCache* tbCacheCreate(void);

void tbCacheDestroy(tbCache* cache);

/* tbCacheLibInit must be called once before using the Token Binding library to
   verify Token Binding headers.  The nonce value will be used to randomize
   hashing in the message cache, defending against certain collision attacks.
   If used in a client that does not verify Token Binding headers, this function
   does not need to be called.  |nonce| must not be 0, which generally is safe
   to assume when using a solid true random number generator. */
void tbCacheLibInit(uint64_t nonce);

/* All the tbCache methods set a status code on the cache object. */
typedef enum {
  TB_CACHE_OK,
  TB_CACHE_BAD_SIGNATURE,
  TB_CACHE_GOOD_SIGNATURE,
  TB_CACHE_HIT,
  TB_CACHE_INVALID_FORMAT,
  TB_CACHE_MEMORY_ERROR,
  TB_CACHE_MISS,
  TB_CACHE_OVERFLOW,
} tbCacheStatus;

/* tbCacheGetStatus returns the status code set by the last method call. */
tbCacheStatus tbCacheGetStatus(tbCache* cache);

/* tbCacheMessageAlreadyVerified checks to see if the message is in the cache of
   messages that have already been verified using this tbCache.  This must be
   called before calling tbCacheVerifyTokenBindingMessage.  False is returned if
   |message| is not in the cache.  No checks for validity are performed.  If the
   message has been verified before, |tokbind_id| is set to the portion of
   |message| representing the public key (the TokenBindingID).  If there is a
   referred token binding, then referred_pubkey is set as well.  This function
   is separate from tbCacheVerifyTokenBindingMessage so that the caller will not
   need to generate the EKM value if we have already verified the message.  The
   output parameters may not be NULL. */
bool tbCacheMessageAlreadyVerified(tbCache* cache, const uint8_t* message,
                                   size_t message_len, uint8_t** out_tokbind_id,
                                   size_t* out_tokbind_id_len,
                                   uint8_t** out_referred_tokbind_id,
                                   size_t* out_referred_tokbind_id_len);

/* tbCacheVerifyTokenBindingMessage parses a token binding message in |message|,
   and verifies that it contains a valid signature of |ekm|.  It can be compute
   intensive, so tbCacheMessageAlreadyVerified must be called first to see if
   verification is required.  False is returned if |message| cannot be parsed,
   if the signature is invalid, or if the key type in the Token Binding Message
   does not match |expected_key_type|.  The key type should be determined from
   the TLS negotiation.  On success, |tokbind_id| is set to the portion of
   |message| representing the public key (the TokenBindingID).  The token
   binding message can optionally contain a "referred" token binding, which is
   used in federated scenarios.  The key type for a referred token binding can
   be different than |expected_key_type|, so use
   tbGetKeyType(referred_tokbind_id) to get the referred key type.
   |referred_tokbind_id| will be set to the referred public key if present in the
   token binding message, or NULL if not.  The output parameters may not be
   NULL. */
bool tbCacheVerifyTokenBindingMessage(
    tbCache* cache, const uint8_t* message, size_t message_len,
    tbKeyType expected_key_type, const uint8_t ekm[TB_HASH_LEN],
    uint8_t** out_tokbind_id, size_t* out_tokbind_id_len,
    uint8_t** out_referred_tokbind_id, size_t* out_referred_tokbind_id_len);

/* tbDecodeTokenBindingID converts a key string in token Binding format
   (TokenBindingID) to a Token Binding compatible EVP_PKEY, and sets
   |out_key_type| to the Token Binding type of the key.  If |key| is not a valid
   Token Binding key, NULL is returned.  Call tbEncodeKey to convert an EVP_PKEY
   object to Token Binding format.  The caller takes ownership of the returned
   EVP_PKEY. */
EVP_PKEY* tbDecodeTokenBindingID(const uint8_t* tokbind_id,
                                 size_t tokbind_id_len,
                                 tbKeyType* out_key_type);

#endif  /* TOKEN_BIND_TOKEN_BIND_SERVER_H_ */
