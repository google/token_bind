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

/* This is a simple utility to translate web-base64 to hex. */

#include <base64.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "token_bind_server.h"

static void printHex(char *label, char* message, size_t message_len) {
  printf("%s:", label);
  size_t i;
  for (i = 0; i < message_len; i++) {
    printf(" %02x", (uint8_t)message[i]);
  }
  printf("\n");
}

static bool readLine(char* line) {
  int pos = 0;
  int c;
  while ((c = getchar()) != '\n' && c != EOF) {
    line[pos++] = c;
  }
  line[pos] = '\0';
  return c != EOF;
}

int main() {
  tbCacheLibInit(0xdeadbeef);
  tbCache* tokbind_cache = tbCacheCreate();
  char line[1024];
  char buf[1024];
  uint8_t ekm[32] = {0,};
  while(readLine(line)) {
    size_t len = WebSafeBase64Unescape(line, buf, 1024);
    printHex("TB header", buf, len);
    uint8_t* tokbind_id;
    uint8_t* referred_tokbind_id;
    size_t tokbind_id_len, referred_tokbind_id_len;
    tbCacheVerifyTokenBindingMessage(
          tokbind_cache, (uint8_t*)buf, len,
          TB_ECDSAP256, ekm, &tokbind_id, &tokbind_id_len,
          &referred_tokbind_id, &referred_tokbind_id_len);
    printf("status: %s\n",
           tbCacheGetStatusString(tbCacheGetStatus(tokbind_cache)));
  }
  return 0;
}
