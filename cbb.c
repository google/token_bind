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

#include <stdlib.h>
#include "tb_bytestring.h"

#include <assert.h>
#include <string.h>

static void tbCBB_zero(tbCBB *cbb) {
  memset(cbb, 0, sizeof(tbCBB));
}

static int cbb_init(tbCBB *cbb, uint8_t *buf, size_t cap) {
  /* This assumes that |cbb| has already been zeroed. */
  struct tb_cbb_buffer_st *base;

  base = malloc(sizeof(struct tb_cbb_buffer_st));
  if (base == NULL) {
    return 0;
  }

  base->buf = buf;
  base->len = 0;
  base->cap = cap;
  base->can_resize = 1;
  base->error = 0;

  cbb->base = base;
  cbb->is_top_level = 1;
  return 1;
}

int tbCBB_init(tbCBB *cbb, size_t initial_capacity) {
  tbCBB_zero(cbb);

  uint8_t *buf = malloc(initial_capacity);
  if (initial_capacity > 0 && buf == NULL) {
    return 0;
  }

  if (!cbb_init(cbb, buf, initial_capacity)) {
    free(buf);
    return 0;
  }

  return 1;
}

void tbCBB_cleanup(tbCBB *cbb) {
  if (cbb->base) {
    /* Only top-level |tbCBB|s are cleaned up. Child |tbCBB|s are non-owning.
     * They are implicitly discarded when the parent is flushed or cleaned up.
     */
    assert(cbb->is_top_level);

    if (cbb->base->can_resize) {
      free(cbb->base->buf);
    }
    free(cbb->base);
  }
  cbb->base = NULL;
}

static int cbb_buffer_reserve(struct tb_cbb_buffer_st *base, uint8_t **out,
                              size_t len) {
  size_t newlen;

  if (base == NULL) {
    return 0;
  }

  newlen = base->len + len;
  if (newlen < base->len) {
    /* Overflow */
    goto err;
  }

  if (newlen > base->cap) {
    size_t newcap = base->cap * 2;
    uint8_t *newbuf;

    if (!base->can_resize) {
      goto err;
    }

    if (newcap < base->cap || newcap < newlen) {
      newcap = newlen;
    }
    newbuf = realloc(base->buf, newcap);
    if (newbuf == NULL) {
      goto err;
    }

    base->buf = newbuf;
    base->cap = newcap;
  }

  if (out) {
    *out = base->buf + base->len;
  }

  return 1;

err:
  base->error = 1;
  return 0;
}

static int cbb_buffer_add(struct tb_cbb_buffer_st *base, uint8_t **out,
                          size_t len) {
  if (!cbb_buffer_reserve(base, out, len)) {
    return 0;
  }
  /* This will not overflow or |cbb_buffer_reserve| would have failed. */
  base->len += len;
  return 1;
}

static int cbb_buffer_add_u(struct tb_cbb_buffer_st *base, uint32_t v,
                            size_t len_len) {
  uint8_t *buf;
  size_t i;

  if (len_len == 0) {
    return 1;
  }
  if (!cbb_buffer_add(base, &buf, len_len)) {
    return 0;
  }

  for (i = len_len - 1; i < len_len; i--) {
    buf[i] = v;
    v >>= 8;
  }

  if (v != 0) {
    base->error = 1;
    return 0;
  }

  return 1;
}

int tbCBB_finish(tbCBB *cbb, uint8_t **out_data, size_t *out_len) {
  if (!cbb->is_top_level) {
    return 0;
  }

  if (!tbCBB_flush(cbb)) {
    return 0;
  }

  if (cbb->base->can_resize && (out_data == NULL || out_len == NULL)) {
    /* |out_data| and |out_len| can only be NULL if the tbCBB is fixed. */
    return 0;
  }

  if (out_data != NULL) {
    *out_data = cbb->base->buf;
  }
  if (out_len != NULL) {
    *out_len = cbb->base->len;
  }
  cbb->base->buf = NULL;
  tbCBB_cleanup(cbb);
  return 1;
}

/* tbCBB_flush recurses and then writes out any pending length prefix. The
 * current length of the underlying base is taken to be the length of the
 * length-prefixed data. */
int tbCBB_flush(tbCBB *cbb) {
  size_t child_start, i, len;

  /* If |cbb->base| has hit an error, the buffer is in an undefined state, so
   * fail all following calls. In particular, |cbb->child| may point to invalid
   * memory. */
  if (cbb->base == NULL || cbb->base->error) {
    return 0;
  }

  if (cbb->child == NULL || cbb->child->pending_len_len == 0) {
    return 1;
  }

  child_start = cbb->child->offset + cbb->child->pending_len_len;

  if (!tbCBB_flush(cbb->child) || child_start < cbb->child->offset ||
      cbb->base->len < child_start) {
    goto err;
  }

  len = cbb->base->len - child_start;

  if (cbb->child->pending_is_asn1) {
    /* For ASN.1 we assume that we'll only need a single byte for the length.
     * If that turned out to be incorrect, we have to move the contents along
     * in order to make space. */
    uint8_t len_len;
    uint8_t initial_length_byte;

    assert(cbb->child->pending_len_len == 1);

    if (len > 0xfffffffe) {
      /* Too large. */
      goto err;
    } else if (len > 0xffffff) {
      len_len = 5;
      initial_length_byte = 0x80 | 4;
    } else if (len > 0xffff) {
      len_len = 4;
      initial_length_byte = 0x80 | 3;
    } else if (len > 0xff) {
      len_len = 3;
      initial_length_byte = 0x80 | 2;
    } else if (len > 0x7f) {
      len_len = 2;
      initial_length_byte = 0x80 | 1;
    } else {
      len_len = 1;
      initial_length_byte = (uint8_t)len;
      len = 0;
    }

    if (len_len != 1) {
      /* We need to move the contents along in order to make space. */
      size_t extra_bytes = len_len - 1;
      if (!cbb_buffer_add(cbb->base, NULL, extra_bytes)) {
        goto err;
      }
      memmove(cbb->base->buf + child_start + extra_bytes,
              cbb->base->buf + child_start, len);
    }
    cbb->base->buf[cbb->child->offset++] = initial_length_byte;
    cbb->child->pending_len_len = len_len - 1;
  }

  for (i = cbb->child->pending_len_len - 1; i < cbb->child->pending_len_len;
       i--) {
    cbb->base->buf[cbb->child->offset + i] = (uint8_t)len;
    len >>= 8;
  }
  if (len != 0) {
    goto err;
  }

  cbb->child->base = NULL;
  cbb->child = NULL;

  return 1;

err:
  cbb->base->error = 1;
  return 0;
}

const uint8_t *tbCBB_data(const tbCBB *cbb) {
  assert(cbb->child == NULL);
  return cbb->base->buf + cbb->offset + cbb->pending_len_len;
}

size_t tbCBB_len(const tbCBB *cbb) {
  assert(cbb->child == NULL);
  assert(cbb->offset + cbb->pending_len_len <= cbb->base->len);

  return cbb->base->len - cbb->offset - cbb->pending_len_len;
}

static int cbb_add_length_prefixed(tbCBB *cbb, tbCBB *out_contents,
                                   uint8_t len_len) {
  uint8_t *prefix_bytes;

  if (!tbCBB_flush(cbb)) {
    return 0;
  }

  size_t offset = cbb->base->len;
  if (!cbb_buffer_add(cbb->base, &prefix_bytes, len_len)) {
    return 0;
  }

  memset(prefix_bytes, 0, len_len);
  memset(out_contents, 0, sizeof(tbCBB));
  out_contents->base = cbb->base;
  cbb->child = out_contents;
  cbb->child->offset = offset;
  cbb->child->pending_len_len = len_len;
  cbb->child->pending_is_asn1 = 0;

  return 1;
}

int tbCBB_add_u8_length_prefixed(tbCBB *cbb, tbCBB *out_contents) {
  return cbb_add_length_prefixed(cbb, out_contents, 1);
}

int tbCBB_add_u16_length_prefixed(tbCBB *cbb, tbCBB *out_contents) {
  return cbb_add_length_prefixed(cbb, out_contents, 2);
}

int tbCBB_add_asn1(tbCBB *cbb, tbCBB *out_contents, unsigned tag) {
  if (tag > 0xff || (tag & 0x1f) == 0x1f) {
    /* Long form identifier octets are not supported. Further, all current valid
     * tag serializations are 8 bits. */
    cbb->base->error = 1;
    return 0;
  }

  if (!tbCBB_flush(cbb) ||
      /* |tag|'s representation matches the DER encoding. */
      !tbCBB_add_u8(cbb, (uint8_t)tag)) {
    return 0;
  }

  size_t offset = cbb->base->len;
  if (!tbCBB_add_u8(cbb, 0)) {
    return 0;
  }

  memset(out_contents, 0, sizeof(tbCBB));
  out_contents->base = cbb->base;
  cbb->child = out_contents;
  cbb->child->offset = offset;
  cbb->child->pending_len_len = 1;
  cbb->child->pending_is_asn1 = 1;

  return 1;
}

int tbCBB_add_bytes(tbCBB *cbb, const uint8_t *data, size_t len) {
  uint8_t *dest;

  if (!tbCBB_flush(cbb) || !cbb_buffer_add(cbb->base, &dest, len)) {
    return 0;
  }
  memcpy(dest, data, len);
  return 1;
}

int tbCBB_add_u8(tbCBB *cbb, uint8_t value) {
  if (!tbCBB_flush(cbb)) {
    return 0;
  }

  return cbb_buffer_add_u(cbb->base, value, 1);
}

int tbCBB_add_u16(tbCBB *cbb, uint16_t value) {
  if (!tbCBB_flush(cbb)) {
    return 0;
  }

  return cbb_buffer_add_u(cbb->base, value, 2);
}
