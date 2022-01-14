// Copyright 2018 Jean-Baptiste Bédrune <jb@security-labs.org>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "lzp.h"
#include <malloc.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define LZP_ORDER 4

static unsigned int *hash_table = NULL;
static bool lzp_initialized = false;

static unsigned int hash_index(unsigned int c) {
  unsigned int h;

  c = __builtin_bswap32(c);
  h = ((c >> 15u) ^ c) & 0xffffu;
  return h;
}

size_t lzp_unpack(const uint8_t *input_data, size_t input_size,
                  uint8_t *output_data, size_t output_size) {
  unsigned int written, read;
  unsigned int mask;
  unsigned char b;
  int i, j;
  int pos;
  unsigned int c;
  unsigned int h;
  uint8_t *p;

  written = 0;
  read = 0;

  memset(output_data, 0, output_size);

  p = output_data;

  for (i = 0; i < LZP_ORDER; i++) {
    *p++ = input_data[read++];
    written++;
  }

  c = *(uint32_t *)(output_data - LZP_ORDER);
  h = hash_index(c);
  hash_table[h] = written;

  while ((written < output_size) && (read < input_size)) {
    mask = input_data[read++];
    for (i = 0; i < 8; i++) {
      b = input_data[read++];

      if (!(mask & 0x80u)) {
        // literals. update dictionary
        c = *(uint32_t *)(p - LZP_ORDER);
        h = hash_index(c);
        hash_table[h] = written;

        *p++ = b;
        written++;

        if (written == output_size)
          goto done;
      } else {
        // match. read dictionary
        c = *(uint32_t *)(p - LZP_ORDER);
        h = hash_index(c);
        pos = hash_table[h];
        hash_table[h] = written;

        for (j = 0; j < b; j++) {
          *p++ = output_data[pos + j];
          written += 1;

          if (written == output_size) {
            goto done;
          }
        }
      }

      mask <<= 1;
    }
  }
done:
  return written;
}

bool lzp_init() {
  if (!lzp_initialized) {
    hash_table = malloc(sizeof(unsigned int) * 0x10000);
    if (hash_table == NULL) {
      return false;
    }
    lzp_initialized = true;
  }

  for (int i = 0; i < 0x10000; i++) {
    hash_table[i] = ~0u;
    ;
  }
  return true;
}

void lzp_destroy() {
  if (lzp_initialized) {
    free(hash_table);
    lzp_initialized = false;
  }
}
