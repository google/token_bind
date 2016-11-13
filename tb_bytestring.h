/* Copyright 2014 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License. */

/* This file was copied from BoringSSL and stripped of functions not used by the
 * token binding libraries. */

#ifndef TOKEN_BIND_CSRC_TB_BYTESTRING_H
#define TOKEN_BIND_CSRC_TB_BYTESTRING_H

/* If using BoringSSL, this will now be defined.  This file must be included
 * after the source file includes a public OpenSSL header, such as
 * <openssl/evp.h> or <openssl/ssl.h> */
#ifdef OPENSSL_IS_BORINGSSL

/* Use BoringSSL's versions of these functions. */

#include <openssl/bytestring.h>

#define tbCBS CBS
#define tbCBS_init CBS_init
#define tbCBS_data CBS_data
#define tbCBS_len CBS_len
#define tbCBS_get_u8 CBS_get_u8
#define tbCBS_get_u16 CBS_get_u16
#define tbCBS_get_bytes CBS_get_bytes
#define tbCBS_get_u8_length_prefixed CBS_get_u8_length_prefixed
#define tbCBS_get_u16_length_prefixed CBS_get_u16_length_prefixed
#define tbCBS_ASN1_INTEGER CBS_ASN1_INTEGER
#define tbCBS_ASN1_SEQUENCE CBS_ASN1_SEQUENCE
#define tbCBS_ASN1_CONSTRUCTED CBS_ASN1_CONSTRUCTED
#define tbCBS_get_asn1 CBS_get_asn1
#define tbCBS_get_asn1_element CBS_get_asn1_element
#define tbCBS_get_any_asn1_element CBS_get_any_asn1_element
#define tbCBB CBB
#define tbCBB_init CBB_init
#define tbCBB_cleanup CBB_cleanup
#define tbCBB_finish CBB_finish
#define tbCBB_flush CBB_flush
#define tbCBB_data CBB_data
#define tbCBB_len CBB_len
#define tbCBB_add_u8_length_prefixed CBB_add_u8_length_prefixed
#define tbCBB_add_u16_length_prefixed CBB_add_u16_length_prefixed
#define tbCBB_add_asn1 CBB_add_asn1
#define tbCBB_add_bytes CBB_add_bytes
#define tbCBB_add_u8 CBB_add_u8
#define tbCBB_add_u16 CBB_add_u16

#else

/* When using OpenSSL, link in these functions copied from BoringSSL. */

/* Bytestrings are used for parsing and building TLS and ASN.1 messages.
 *
 * A "tbCBS" (CRYPTO ByteString) represents a string of bytes in memory and
 * provides utility functions for safely parsing length-prefixed structures
 * like TLS and ASN.1 from it.
 *
 * A "tbCBB" (CRYPTO ByteBuilder) is a memory buffer that grows as needed and
 * provides utility functions for building length-prefixed messages. */

#include <stddef.h>
#include <stdint.h>

/* CRYPTO ByteString */

struct tbcbs_st {
  const uint8_t *data;
  size_t len;
};

typedef struct tbcbs_st tbCBS;

/* tbCBS_init sets |cbs| to point to |data|. It does not take ownership of
 * |data|. */
void tbCBS_init(tbCBS *cbs, const uint8_t *data, size_t len);

/* tbCBS_data returns a pointer to the contents of |cbs|. */
const uint8_t *tbCBS_data(const tbCBS *cbs);

/* tbCBS_len returns the number of bytes remaining in |cbs|. */
size_t tbCBS_len(const tbCBS *cbs);

/* tbCBS_get_u8 sets |*out| to the next uint8_t from |cbs| and advances |cbs|.
 * It returns one on success and zero on error. */
int tbCBS_get_u8(tbCBS *cbs, uint8_t *out);

/* tbCBS_get_u16 sets |*out| to the next, big-endian uint16_t from |cbs| and
 * advances |cbs|. It returns one on success and zero on error. */
int tbCBS_get_u16(tbCBS *cbs, uint16_t *out);

/* tbCBS_get_bytes sets |*out| to the next |len| bytes from |cbs| and advances
 * |cbs|. It returns one on success and zero on error. */
int tbCBS_get_bytes(tbCBS *cbs, tbCBS *out, size_t len);

/* tbCBS_get_u8_length_prefixed sets |*out| to the contents of an 8-bit,
 * length-prefixed value from |cbs| and advances |cbs| over it. It returns one
 * on success and zero on error. */
int tbCBS_get_u8_length_prefixed(tbCBS *cbs, tbCBS *out);

/* tbCBS_get_u16_length_prefixed sets |*out| to the contents of a 16-bit,
 * big-endian, length-prefixed value from |cbs| and advances |cbs| over it. It
 * returns one on success and zero on error. */
int tbCBS_get_u16_length_prefixed(tbCBS *cbs, tbCBS *out);

/* Parsing ASN.1 */

/* The following values are tag numbers for UNIVERSAL elements. */
#define tbCBS_ASN1_INTEGER 0x2
#define tbCBS_ASN1_SEQUENCE (0x10 | tbCBS_ASN1_CONSTRUCTED)

/* tbCBS_ASN1_CONSTRUCTED may be ORed into a tag to toggle the constructed
 * bit. |tbCBS| and |tbCBB| APIs consider the constructed bit to be part of the
 * tag. */
#define tbCBS_ASN1_CONSTRUCTED 0x20

/* tbCBS_get_asn1 sets |*out| to the contents of DER-encoded, ASN.1 element (not
 * including tag and length bytes) and advances |cbs| over it. The ASN.1 element
 * must match |tag_value|. It returns one on success and zero on error.
 *
 * Tag numbers greater than 30 are not supported (i.e. short form only). */
int tbCBS_get_asn1(tbCBS *cbs, tbCBS *out, unsigned tag_value);

/* tbCBS_get_asn1_element acts like |tbCBS_get_asn1| but |out| will include the
 * ASN.1 header bytes too. */
int tbCBS_get_asn1_element(tbCBS *cbs, tbCBS *out, unsigned tag_value);

/* tbCBS_get_any_asn1_element sets |*out| to contain the next ASN.1 element from
 * |*cbs| (including header bytes) and advances |*cbs|. It sets |*out_tag| to
 * the tag number and |*out_header_len| to the length of the ASN.1 header. Each
 * of |out|, |out_tag|, and |out_header_len| may be NULL to ignore the value.
 *
 * Tag numbers greater than 30 are not supported (i.e. short form only). */
int tbCBS_get_any_asn1_element(tbCBS *cbs, tbCBS *out, unsigned *out_tag,
                               size_t *out_header_len);

/* CRYPTO ByteBuilder.
 *
 * |tbCBB| objects allow one to build length-prefixed serialisations. A |tbCBB|
 * object is associated with a buffer and new buffers are created with
 * |tbCBB_init|. Several |tbCBB| objects can point at the same buffer when a
 * length-prefix is pending, however only a single |tbCBB| can be 'current' at
 * any one time. For example, if one calls |tbCBB_add_u8_length_prefixed| then
 * the new |tbCBB| points at the same buffer as the original. But if the
 * original |tbCBB| is used then the length prefix is written out and the new
 * |tbCBB| must not be used again.
 *
 * If one needs to force a length prefix to be written out because a |tbCBB| is
 * going out of scope, use |tbCBB_flush|. If an operation on a |tbCBB| fails, it
 * is in an undefined state and must not be used except to call |tbCBB_cleanup|.
 */

struct tb_cbb_buffer_st {
  uint8_t *buf;
  size_t len;      /* The number of valid bytes. */
  size_t cap;      /* The size of buf. */
  /* One iff |buf| is owned by this object. If not then |buf| cannot be
   * resized. */
  char can_resize;
 /* One iff there was an error writing to this tbCBB. All future operations will
  * fail. */
  char error;
};

struct tbcbb_st;
typedef struct tbcbb_st tbCBB;

struct tbcbb_st {
  struct tb_cbb_buffer_st *base;
  /* child points to a child tbCBB if a length-prefix is pending. */
  tbCBB *child;
  /* offset is the number of bytes from the start of |base->buf| to this
   * |tbCBB|'s pending length prefix. */
  size_t offset;
  /* pending_len_len contains the number of bytes in this |tbCBB|'s pending
   * length-prefix, or zero if no length-prefix is pending. */
  uint8_t pending_len_len;
  char pending_is_asn1;
  /* is_top_level is true iff this is a top-level |tbCBB| (as opposed to a child
   * |tbCBB|). Top-level objects are valid arguments for |tbCBB_finish|. */
  char is_top_level;
};

/* tbCBB_init initialises |cbb| with |initial_capacity|. Since a |tbCBB| grows
 * as needed, the |initial_capacity| is just a hint. It returns one on success
 * or zero on error. */
int tbCBB_init(tbCBB *cbb, size_t initial_capacity);

/* tbCBB_cleanup frees all resources owned by |cbb| and other |tbCBB| objects
 * writing to the same buffer. This should be used in an error case where a
 * serialisation is abandoned.
 *
 * This function can only be called on a "top level" |tbCBB|, i.e. one
 * initialised with |tbCBB_init| or |tbCBB_init_fixed|, or a |tbCBB| set to the
 * zero state with |tbCBB_zero|. */
void tbCBB_cleanup(tbCBB *cbb);

/* tbCBB_finish completes any pending length prefix and sets |*out_data| to a
 * malloced buffer and |*out_len| to the length of that buffer. The caller
 * takes ownership of the buffer and, unless the buffer was fixed with
 * |tbCBB_init_fixed|, must call |OPENSSL_free| when done.
 *
 * It can only be called on a "top level" |tbCBB|, i.e. one initialised with
 * |tbCBB_init| or |tbCBB_init_fixed|. It returns one on success and zero on
 * error. */
int tbCBB_finish(tbCBB *cbb, uint8_t **out_data, size_t *out_len);

/* tbCBB_flush causes any pending length prefixes to be written out and any
 * child |tbCBB| objects of |cbb| to be invalidated. It returns one on success
 * or zero on error. */
int tbCBB_flush(tbCBB *cbb);

/* tbCBB_data returns a pointer to the bytes written to |cbb|. It does not flush
 * |cbb|. The pointer is valid until the next operation to |cbb|.
 *
 * To avoid unfinalized length prefixes, it is a fatal error to call this on a
 * tbCBB with any active children. */
const uint8_t *tbCBB_data(const tbCBB *cbb);

/* tbCBB_len returns the number of bytes written to |cbb|. It does not flush
 * |cbb|.
 *
 * To avoid unfinalized length prefixes, it is a fatal error to call this on a
 * tbCBB with any active children. */
size_t tbCBB_len(const tbCBB *cbb);

/* tbCBB_add_u8_length_prefixed sets |*out_contents| to a new child of |cbb|.
 * The data written to |*out_contents| will be prefixed in |cbb| with an 8-bit
 * length. It returns one on success or zero on error. */
int tbCBB_add_u8_length_prefixed(tbCBB *cbb, tbCBB *out_contents);

/* tbCBB_add_u16_length_prefixed sets |*out_contents| to a new child of |cbb|.
 * The data written to |*out_contents| will be prefixed in |cbb| with a 16-bit,
 * big-endian length. It returns one on success or zero on error. */
int tbCBB_add_u16_length_prefixed(tbCBB *cbb, tbCBB *out_contents);

/* tbCBB_add_asn1 sets |*out_contents| to a |tbCBB| into which the contents of
 * an ASN.1 object can be written. The |tag| argument will be used as the tag
 * for the object. Passing in |tag| number 31 will return in an error since only
 * single octet identifiers are supported. It returns one on success or zero on
 * error. */
int tbCBB_add_asn1(tbCBB *cbb, tbCBB *out_contents, unsigned tag);

/* tbCBB_add_bytes appends |len| bytes from |data| to |cbb|. It returns one on
 * success and zero otherwise. */
int tbCBB_add_bytes(tbCBB *cbb, const uint8_t *data, size_t len);

/* tbCBB_add_u8 appends an 8-bit number from |value| to |cbb|. It returns one on
 * success and zero otherwise. */
int tbCBB_add_u8(tbCBB *cbb, uint8_t value);

/* tbCBB_add_u16 appends a 16-bit, big-endian number from |value| to |cbb|. It
 * returns one on success and zero otherwise. */
int tbCBB_add_u16(tbCBB *cbb, uint16_t value);

#endif  /* OPENSSL_IS_BORING_SSL */

#endif /* TOKEN_BIND_CSRC_TB_BYTESTRING_*/
