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

#include "token_bind_client.h"

#include <stdlib.h>
#include "tb_bytestring.h"

/* Add a token binding to the token binding message. */
static bool buildTokenBinding(tbCBB* message_contents,
                              uint8_t token_binding_type,
                              const uint8_t* tokbind_id, size_t tokbind_id_len,
                              const uint8_t* signature, size_t signature_len) {
  if (tokbind_id == NULL || tokbind_id_len == 0) {
    return false;
  }
  tbCBB sig_cbb;
  if (!tbCBB_add_u8(message_contents, token_binding_type) ||
      !tbCBB_add_bytes(message_contents, tokbind_id, tokbind_id_len) ||
      !tbCBB_add_u16_length_prefixed(message_contents, &sig_cbb) ||
      !tbCBB_add_bytes(&sig_cbb, signature, signature_len) ||
      /* No extensions, so just add u16 zero. */
      !tbCBB_add_u16(message_contents, 0) ||
      !tbCBB_flush(message_contents)) {
    return false;
  }
  return true;
}

bool tbBuildTokenBindingMessage(const uint8_t* tokbind_id,
                                size_t tokbind_id_len, const uint8_t* signature,
                                size_t signature_len, uint8_t** out_message,
                                size_t* out_message_len) {
  tbCBB tokbind_message, message_contents;
  if (!tbCBB_init(&tokbind_message, 0) || out_message == NULL ||
      out_message_len == NULL ||
      !tbCBB_add_u16_length_prefixed(&tokbind_message, &message_contents) ||
      !buildTokenBinding(&message_contents, TB_PROVIDED, tokbind_id,
                         tokbind_id_len, signature, signature_len) ||
      !tbCBB_finish(&tokbind_message, out_message, out_message_len)) {
    tbCBB_cleanup(&tokbind_message);
    return false;
  }
  return true;
}

bool tbBuildReferredTokenBindingMessage(
    const uint8_t* tokbind_id, size_t tokbind_id_len, const uint8_t* signature,
    size_t signature_len, const uint8_t* referred_tokbind_id,
    size_t referred_tokbind_id_len, const uint8_t* referred_signature,
    size_t referred_signature_len, uint8_t** out_message,
    size_t* out_message_len) {
  tbCBB tokbind_message, message_contents;
  if (!tbCBB_init(&tokbind_message, 0) || out_message == NULL ||
      out_message_len == NULL ||
      !tbCBB_add_u16_length_prefixed(&tokbind_message, &message_contents) ||
      !buildTokenBinding(&message_contents, TB_PROVIDED, tokbind_id,
                         tokbind_id_len, signature, signature_len) ||
      !buildTokenBinding(&message_contents, TB_REFERRED, referred_tokbind_id,
                         referred_tokbind_id_len, referred_signature,
                         referred_signature_len) ||
      !tbCBB_finish(&tokbind_message, out_message, out_message_len)) {
    tbCBB_cleanup(&tokbind_message);
    return false;
  }
  return true;
}

bool tbEncodeKey(tbKeyType key_type, const EVP_PKEY* key,
                 uint8_t** out_tokbind_id, size_t* out_tokbind_id_len) {
  int key_len = i2d_PublicKey((EVP_PKEY*)key, NULL);
  if (key_len < 1) {
    return false;
  }
  uint8_t* buf = malloc(key_len * sizeof(uint8_t));
  if (buf == NULL) {
    return false;
  }
  uint8_t* bufp = buf;
  if (i2d_PublicKey((EVP_PKEY*)key, &bufp) != key_len) {
    free(buf);
    return false;  /* Should never happen. */
  }
  if (!tbConvertDerKeyToTokenBindingID(buf, key_len, key_type, out_tokbind_id,
                                       out_tokbind_id_len)) {
    free(buf);
    return false;
  }
  free(buf);
  return true;
}
