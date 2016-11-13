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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tb_bytestring.h"

void tbCBS_init(tbCBS *cbs, const uint8_t *data, size_t len) {
  cbs->data = data;
  cbs->len = len;
}

static int cbs_get(tbCBS *cbs, const uint8_t **p, size_t n) {
  if (cbs->len < n) {
    return 0;
  }

  *p = cbs->data;
  cbs->data += n;
  cbs->len -= n;
  return 1;
}

static int tbCBS_skip(tbCBS *cbs, size_t len) {
  const uint8_t *dummy;
  return cbs_get(cbs, &dummy, len);
}

const uint8_t *tbCBS_data(const tbCBS *cbs) { return cbs->data; }

size_t tbCBS_len(const tbCBS *cbs) { return cbs->len; }

static int cbs_get_u(tbCBS *cbs, uint32_t *out, size_t len) {
  uint32_t result = 0;
  size_t i;
  const uint8_t *data;

  if (!cbs_get(cbs, &data, len)) {
    return 0;
  }
  for (i = 0; i < len; i++) {
    result <<= 8;
    result |= data[i];
  }
  *out = result;
  return 1;
}

int tbCBS_get_u8(tbCBS *cbs, uint8_t *out) {
  const uint8_t *v;
  if (!cbs_get(cbs, &v, 1)) {
    return 0;
  }
  *out = *v;
  return 1;
}

int tbCBS_get_u16(tbCBS *cbs, uint16_t *out) {
  uint32_t v;
  if (!cbs_get_u(cbs, &v, 2)) {
    return 0;
  }
  *out = v;
  return 1;
}

int tbCBS_get_bytes(tbCBS *cbs, tbCBS *out, size_t len) {
  const uint8_t *v;
  if (!cbs_get(cbs, &v, len)) {
    return 0;
  }
  tbCBS_init(out, v, len);
  return 1;
}

static int cbs_get_length_prefixed(tbCBS *cbs, tbCBS *out, size_t len_len) {
  uint32_t len;
  if (!cbs_get_u(cbs, &len, len_len)) {
    return 0;
  }
  return tbCBS_get_bytes(cbs, out, len);
}

int tbCBS_get_u8_length_prefixed(tbCBS *cbs, tbCBS *out) {
  return cbs_get_length_prefixed(cbs, out, 1);
}

int tbCBS_get_u16_length_prefixed(tbCBS *cbs, tbCBS *out) {
  return cbs_get_length_prefixed(cbs, out, 2);
}

static int cbs_get_any_asn1_element(tbCBS *cbs, tbCBS *out, unsigned *out_tag,
                                    size_t *out_header_len, int ber_ok) {
  uint8_t tag, length_byte;
  tbCBS header = *cbs;
  tbCBS throwaway;

  if (out == NULL) {
    out = &throwaway;
  }

  if (!tbCBS_get_u8(&header, &tag) || !tbCBS_get_u8(&header, &length_byte)) {
    return 0;
  }

  /* ITU-T X.690 section 8.1.2.3 specifies the format for identifiers with a tag
   * number no greater than 30.
   *
   * If the number portion is 31 (0x1f, the largest value that fits in the
   * allotted bits), then the tag is more than one byte long and the
   * continuation bytes contain the tag number. This parser only supports tag
   * numbers less than 31 (and thus single-byte tags). */
  if ((tag & 0x1f) == 0x1f) {
    return 0;
  }

  if (out_tag != NULL) {
    *out_tag = tag;
  }

  size_t len;
  /* The format for the length encoding is specified in ITU-T X.690 section
   * 8.1.3. */
  if ((length_byte & 0x80) == 0) {
    /* Short form length. */
    len = ((size_t)length_byte) + 2;
    if (out_header_len != NULL) {
      *out_header_len = 2;
    }
  } else {
    /* The high bit indicate that this is the long form, while the next 7 bits
     * encode the number of subsequent octets used to encode the length (ITU-T
     * X.690 clause 8.1.3.5.b). */
    const size_t num_bytes = length_byte & 0x7f;
    uint32_t len32;

    if (ber_ok && (tag & tbCBS_ASN1_CONSTRUCTED) != 0 && num_bytes == 0) {
      /* indefinite length */
      if (out_header_len != NULL) {
        *out_header_len = 2;
      }
      return tbCBS_get_bytes(cbs, out, 2);
    }

    /* ITU-T X.690 clause 8.1.3.5.c specifies that the value 0xff shall not be
     * used as the first byte of the length. If this parser encounters that
     * value, num_bytes will be parsed as 127, which will fail the check below.
     */
    if (num_bytes == 0 || num_bytes > 4) {
      return 0;
    }
    if (!cbs_get_u(&header, &len32, num_bytes)) {
      return 0;
    }
    /* ITU-T X.690 section 10.1 (DER length forms) requires encoding the length
     * with the minimum number of octets. */
    if (len32 < 128) {
      /* Length should have used short-form encoding. */
      return 0;
    }
    if ((len32 >> ((num_bytes - 1) * 8)) == 0) {
      /* Length should have been at least one byte shorter. */
      return 0;
    }
    len = len32;
    if (len + 2 + num_bytes < len) {
      /* Overflow. */
      return 0;
    }
    len += 2 + num_bytes;
    if (out_header_len != NULL) {
      *out_header_len = 2 + num_bytes;
    }
  }

  return tbCBS_get_bytes(cbs, out, len);
}

int tbCBS_get_any_asn1_element(tbCBS *cbs, tbCBS *out, unsigned *out_tag,
                               size_t *out_header_len) {
  return cbs_get_any_asn1_element(cbs, out, out_tag, out_header_len,
                                  0 /* DER only */);
}

static int cbs_get_asn1(tbCBS *cbs, tbCBS *out, unsigned tag_value,
                        int skip_header) {
  size_t header_len;
  unsigned tag;
  tbCBS throwaway;

  if (out == NULL) {
    out = &throwaway;
  }

  if (!tbCBS_get_any_asn1_element(cbs, out, &tag, &header_len) ||
      tag != tag_value) {
    return 0;
  }

  if (skip_header && !tbCBS_skip(out, header_len)) {
    assert(0);
    return 0;
  }

  return 1;
}

int tbCBS_get_asn1(tbCBS *cbs, tbCBS *out, unsigned tag_value) {
  return cbs_get_asn1(cbs, out, tag_value, 1 /* skip header */);
}

int tbCBS_get_asn1_element(tbCBS *cbs, tbCBS *out, unsigned tag_value) {
  return cbs_get_asn1(cbs, out, tag_value, 0 /* include header */);
}
