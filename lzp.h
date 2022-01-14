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

#ifndef S7UNPACK_LZP_H
#define S7UNPACK_LZP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LZP_CHUNK_SIZE 0x10000

bool lzp_init();
void lzp_destroy();
size_t lzp_unpack(const uint8_t *input_data, size_t input_size,
                  uint8_t *output_data, size_t output_size);

#endif // S7UNPACK_LZP_H
