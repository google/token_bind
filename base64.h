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

#ifndef TOKEN_BIND_CSRC_BASE64_H_
#define TOKEN_BIND_CSRC_BASE64_H_

#include <stdbool.h>
#include <stddef.h>

/* Return the length to use for the output buffer given to the base64 escape
   routines. Make sure to use the same value for do_padding in both.  This
   function may return 0 if the input length is within 16X of the maximum value
   we can represent with size_t. */
size_t CalculateBase64EscapedLen(size_t input_len, bool do_padding);

/* WebSafeBase64Escape and Base64Escape encode |src| to |dest| using base64
   encoding.  |src| is not null terminated, instead specify len.  |dest| should
   have at least CalculateBase64EscapedLen() length.  Returns the length of
   |dest|.  The WebSafe variation uses '-' instead of '+' and '_' instead of
   '/' so that we can place the output in a URL or cookies without having to
   escape them.  It also has an extra parameter "do_padding", which when set to
   false will prevent padding with "=". */
size_t WebSafeBase64Escape(const char* src, size_t slen, char* dest,
                           size_t szdest, bool do_padding);
size_t Base64Escape(const char* src, size_t szsrc, char* dest, size_t szdest,
                    bool do_padding);

/* WebBase64Unescape and Base64Unscape copy |src| to |dest|, where src is in
   base64 and is written to its ASCII equivalents. |src| is null terminated.
   The WebSafe variation use '-' instead of '+' and '_' instead of '/'.  The
   functions return the number of characters that are decoded in the
   destination buffer or 0 in case of a decoding error.  */
size_t WebSafeBase64Unescape(const char* src, char* dest, size_t szdest);
size_t Base64Unescape(const char* src, char* dest, size_t szdest);

#endif  // TOKEN_BIND_CSRC_BASE64_H_
