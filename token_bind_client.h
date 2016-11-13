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

#ifndef TOKEN_BIND_CSRC_TOKEN_BIND_CLIENT_H_
#define TOKEN_BIND_CSRC_TOKEN_BIND_CLIENT_H_

/* This library implements client-side functionality of Token Binding, as
   specified in: https://datatracker.ietf.org/doc/draft-ietf-tokbind-protocol

   In essence, Token Binding is the next version of Channel ID.  It is on track
   to become an IETF standard. */

#include <openssl/evp.h>
#include "token_bind_common.h"

/* tbBuildTokenBindingMessage can be called by an HTTP client to create a Token
   Binding Message in |out_message| which can be attached to an HTTP request to
   prove possession of the Token Binding private key.  |signature| is a
   signature of |EKM|, using cipher suite specified by GetKeyType(tokbind_id).
   This builds a "provided" token binding.  The caller is responsible for
   calling free on out_message. */
bool tbBuildTokenBindingMessage(const uint8_t* tokbind_id,
                                size_t tokbind_id_len, const uint8_t* signature,
                                size_t signature_len, uint8_t** out_message,
                                size_t* out_message_len);

/* tbBuildReferredTokenBindingMessage can be called by an HTTP client to create
   a Token Binding Message in |out_message| which can be attached to an HTTP
   request to prove possession of the Token Binding private key.  |signature| is
   a signature of |EKM|, using cipher suite specified by GetKeyType(tokbind_id).
   This builds a "provided" token binding, and also a "referred" token binding.
   The caller takes ownership of |out_message|. */
bool tbBuildReferredTokenBindingMessage(
    const uint8_t* tokbind_id, size_t tokbind_id_len, const uint8_t* signature,
    size_t signature_len, const uint8_t* referred_tokbind_id,
    size_t referred_tokbind_id_len, const uint8_t* referred_signature,
    size_t referred_signature_len, uint8_t** out_message,
    size_t* out_message_len);

/* EncodeKey converts a EVP_PKEY object to a TokenBindingID.  The caller takes
   ownership of |out_tokbind_id|. */
bool tbEncodeKey(tbKeyType key_type, const EVP_PKEY* key,
                 uint8_t** out_tokbind_id, size_t* out_tokbind_id_len);

#endif  /* TOKEN_BIND_CSRC_TOKEN_BIND_CLIENT_H_ */
