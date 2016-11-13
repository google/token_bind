/* Copyright 2003-2009, 2016 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License. */

/* This was adapted from Google's Omaha open-source project. */

#include "base64.h"

size_t CalculateBase64EscapedLen(size_t input_len, bool do_padding) {
  /* these formulae were copied from comments that used to go with the base64
     encoding functions */
  if (((input_len << 4) >> 4) != input_len) {
      /* Too large to allocate */
      return 0;
  }
  size_t intermediate_result = 8 * input_len + 5;
  int len = intermediate_result / 6;
  if (do_padding) len = ((len + 3) / 4) * 4;
  return len;
}

static size_t Base64EscapeInternal(const char *src, size_t szsrc,
                                   char *dest, size_t szdest,
                                   const char *base64,
                                   bool do_padding) {
  if (base64 == NULL || dest == NULL || src == NULL || szsrc <= 0) {
    return 0;
  }
  static const char kPad64 = '=';
  char* cur_dest = dest;
  const unsigned char *cur_src = (const unsigned char*)src;

  /* Three bytes of data encodes to four characters of cyphertext.
     So we can pump through three-byte chunks atomically. */
  while (szsrc > 2) {
    /* Keep going until we have less than 24 bits. */
    if (szdest < 4 ) {
        return 0;
    }
    szdest -= 4;
    cur_dest[0] = base64[cur_src[0] >> 2];
    cur_dest[1] = base64[((cur_src[0] & 0x03) << 4) + (cur_src[1] >> 4)];
    cur_dest[2] = base64[((cur_src[1] & 0x0f) << 2) + (cur_src[2] >> 6)];
    cur_dest[3] = base64[cur_src[2] & 0x3f];
    cur_dest += 4;
    cur_src += 3;
    szsrc -= 3;
  }

  /* now deal with the tail (<=2 bytes) */
  switch (szsrc) {
    case 0:
      /* Nothing left; nothing more to do. */
      break;
    case 1:
      /* One byte left: this encodes to two characters, and (optionally)
         two pad characters to round out the four-character cypherblock. */
      if (szdest < 2) {
        return 0;
      }
      szdest -= 2;
      cur_dest[0] = base64[cur_src[0] >> 2];
      cur_dest[1] = base64[(cur_src[0] & 0x03) << 4];
      cur_dest += 2;
      if (do_padding) {
        if (szdest < 2) {
          return 0;
        }
        szdest -= 2;
        cur_dest[0] = kPad64;
        cur_dest[1] = kPad64;
        cur_dest += 2;
      }
      break;
    case 2:
      /* Two bytes left: this encodes to three characters, and (optionally)
         one pad character to round out the four-character cypherblock. */
      if (szdest < 3) {
        return 0;
      }
      szdest -= 3;
      cur_dest[0] = base64[cur_src[0] >> 2];
      cur_dest[1] = base64[((cur_src[0] & 0x03) << 4) + (cur_src[1] >> 4)];
      cur_dest[2] = base64[(cur_src[1] & 0x0f) << 2];
      cur_dest += 3;
      if (do_padding) {
        if (szdest < 1) {
          return 0;
        }
        szdest -= 1;
        cur_dest[0] = kPad64;
        cur_dest += 1;
      }
      break;
    default:
      /* Should not be reached: blocks of 3 bytes are handled
         in the while loop before this switch statement. */
      return 0;
  }
  return cur_dest - dest;
}

#define kBase64Chars  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

#define kWebSafeBase64Chars "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

size_t Base64Escape(const char* src, size_t szsrc, char* dest, size_t szdest,
                    bool do_padding) {
  return Base64EscapeInternal(src, szsrc, dest, szdest, kBase64Chars, do_padding);
}

size_t WebSafeBase64Escape(const char* src, size_t szsrc, char* dest,
                           size_t szdest, bool do_padding) {
  return Base64EscapeInternal(src, szsrc, dest, szdest, kWebSafeBase64Chars,
                              do_padding);
}

/* Check out
   http://www.cis.ohio-state.edu/htbin/rfc/rfc2045.html for formal
   description, but what we care about is that...
     Take the encoded stuff in groups of 4 characters and turn each
     character into a code 0 to 63 thus:
             A-Z map to 0 to 25
             a-z map to 26 to 51
             0-9 map to 52 to 61
             +(- for WebSafe) maps to 62
             /(_ for WebSafe) maps to 63
     There will be four numbers, all less than 64 which can be represented
     by a 6 digit binary number (aaaaaa, bbbbbb, cccccc, dddddd respectively).
     Arrange the 6 digit binary numbers into three bytes as such:
     aaaaaabb bbbbcccc ccdddddd
     Equals signs (one or two) are used at the end of the encoded block to
     indicate that the text was not an integer multiple of three bytes long. */
static size_t Base64UnescapeInternal(const char* src,
                                     char* dest, size_t len_dest,
                                     const char* unbase64) {
  if (unbase64 == NULL || src == NULL || dest == NULL) {
    return 0;
  }
  static const char kPad64 = '=';
  int decode;
  size_t destidx = 0;
  int state = 0;
  /* Used an unsigned char, since ch is used as an array index
     (into unbase64).  */
  unsigned char ch = 0;
  while ((ch = *src++) != '\0')  {
    if (ch < ' ') {
      continue; /* Skip whitespace */
    }
    if (ch == kPad64) {
      break;
    }
    decode = unbase64[ch];
    if (decode == 99) {
      return 0;  /* A non-base64 character */
    }
    /* Four cyphertext characters decode to three bytes.  Therefore we can be
       in one of four states. */
    switch (state) {
      case 0:
        /* We're at the beginning of a four-character cyphertext block.
           This sets the high six bits of the first byte of the plaintext
           block. */
        if (destidx >= len_dest) {
          return 0;
        }
        dest[destidx] = (char)(decode << 2);
        state = 1;
        break;
      case 1:
        /* We're one character into a four-character cyphertext block.  This
           sets the low two bits of the first plaintext byte, and the high four
           bits of the second plaintext byte.  However, if this is the end of
           data, and those four bits are zero, it could be that those four bits
           are leftovers from the encoding of data that had a length of one mod
           three. */
        if (destidx >= len_dest) {
          return 0;
        }
        dest[destidx] |= decode >> 4;
        if (destidx + 1 >= len_dest) {
          if ((decode & 0x0f) != 0) {
            return 0;
          }
        } else {
          dest[destidx + 1] = (char)((decode & 0x0f) << 4);
        }
        destidx++;
        state = 2;
        break;
      case 2:
        /* We're two characters into a four-character cyphertext block.  This
           sets the low four bits of the second plaintext byte, and the high
           two bits of the third plaintext byte.  However, if this is the end
           of data, and those two bits are zero, it could be that those two
           bits are leftovers from the encoding of data that had a length of
           two mod three. */
        if (destidx >= len_dest) {
          return 0;
        }
        dest[destidx] |= decode >> 2;
        if (destidx +1 >= len_dest) {
          if ((decode & 0x03) != 0) {
            return (-1);
          }
        } else {
          dest[destidx + 1] = (char)((decode & 0x03) << 6);
        }
        destidx++;
        state = 3;
        break;
      case 3:
        /* We're at the last character of a four-character cyphertext block.
           This sets the low six bits of the third plaintext byte. */
        if (destidx >= len_dest) {
          return 0;
        }
        dest[destidx] |= decode;
        destidx++;
        state = 0;
        break;
    default:
      return 0;
      break;
    }
  }

  /* We are done decoding Base-64 chars.  Let's see if we ended on a byte
     boundary, and/or with erroneous trailing characters. */
  if (ch == kPad64) {  /* We got a pad char */
    if (state == 0 || state == 1) {
      return 0;  /* Invalid '=' in first or second position */
    }
    if (state == 2) {
      /* need another '=' */
      while ((ch = *src++) != '\0') {
        if (ch < ' ') {
          break;
        }
      }
      if (ch != kPad64) {
        return 0;
      }
    }
    /* state = 1 or 2, check if all remain padding is space/ */
    while ((ch = *src++) != '\0') {
      if (ch > ' ') {
        return 0;
      }
    }
  } else {
    /* We ended by seeing the end of the string.  Make sure we have no partial
       bytes lying around.  Note that we do not require trailing '=', so states
       2 and 3 are okay too. */
    if (state == 1)
      return 0;
  }
  return destidx;
}

size_t Base64Unescape(const char* src, char* dest,
                      size_t len_dest) {
  static const char UnBase64[] = {
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      62/*+*/, 99,      99,      99,      63/*/ */,
     52/*0*/, 53/*1*/, 54/*2*/, 55/*3*/, 56/*4*/, 57/*5*/, 58/*6*/, 59/*7*/,
     60/*8*/, 61/*9*/, 99,      99,      99,      99,      99,      99,
     99,       0/*A*/,  1/*B*/,  2/*C*/,  3/*D*/,  4/*E*/,  5/*F*/,  6/*G*/,
      7/*H*/,  8/*I*/,  9/*J*/, 10/*K*/, 11/*L*/, 12/*M*/, 13/*N*/, 14/*O*/,
     15/*P*/, 16/*Q*/, 17/*R*/, 18/*S*/, 19/*T*/, 20/*U*/, 21/*V*/, 22/*W*/,
     23/*X*/, 24/*Y*/, 25/*Z*/, 99,      99,      99,      99,      99,
     99,      26/*a*/, 27/*b*/, 28/*c*/, 29/*d*/, 30/*e*/, 31/*f*/, 32/*g*/,
     33/*h*/, 34/*i*/, 35/*j*/, 36/*k*/, 37/*l*/, 38/*m*/, 39/*n*/, 40/*o*/,
     41/*p*/, 42/*q*/, 43/*r*/, 44/*s*/, 45/*t*/, 46/*u*/, 47/*v*/, 48/*w*/,
     49/*x*/, 50/*y*/, 51/*z*/, 99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99,
     99,      99,      99,      99,      99,      99,      99,      99
  };
  return Base64UnescapeInternal(src, dest, len_dest, UnBase64);
}

size_t WebSafeBase64Unescape(const char *src, char *dest, size_t szdest) {
  static const char UnBase64[] = {
    99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      62/*-*/, 99,      99,
      52/*0*/, 53/*1*/, 54/*2*/, 55/*3*/, 56/*4*/, 57/*5*/, 58/*6*/, 59/*7*/,
      60/*8*/, 61/*9*/, 99,      99,      99,      99,      99,      99,
      99,       0/*A*/,  1/*B*/,  2/*C*/,  3/*D*/,  4/*E*/,  5/*F*/,  6/*G*/,
      7/*H*/,  8/*I*/,  9/*J*/, 10/*K*/, 11/*L*/, 12/*M*/, 13/*N*/, 14/*O*/,
      15/*P*/, 16/*Q*/, 17/*R*/, 18/*S*/, 19/*T*/, 20/*U*/, 21/*V*/, 22/*W*/,
      23/*X*/, 24/*Y*/, 25/*Z*/, 99,      99,      99,      99,      63/*_*/,
      99,      26/*a*/, 27/*b*/, 28/*c*/, 29/*d*/, 30/*e*/, 31/*f*/, 32/*g*/,
      33/*h*/, 34/*i*/, 35/*j*/, 36/*k*/, 37/*l*/, 38/*m*/, 39/*n*/, 40/*o*/,
      41/*p*/, 42/*q*/, 43/*r*/, 44/*s*/, 45/*t*/, 46/*u*/, 47/*v*/, 48/*w*/,
      49/*x*/, 50/*y*/, 51/*z*/, 99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99,
      99,      99,      99,      99,      99,      99,      99,      99
  };
  return Base64UnescapeInternal(src, dest, szdest, UnBase64);
}
