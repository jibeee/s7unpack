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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FW_HEADER_SIZE 0x2c
#define FW_NUM_ENTRIES 4
#define FW_ENTRY_NAME_SIZE 6

typedef struct {
  uint32_t size;
  uint32_t crc;
  char name[FW_ENTRY_NAME_SIZE];
} __attribute__((packed)) fw_raw_entry;

typedef struct {
  long offset;
  uint32_t size;
  uint32_t crc;
  char name[FW_ENTRY_NAME_SIZE + 1];
} fw_entry;

static bool get_firmware_entry(FILE *f, const char *name, fw_entry *entry) {
  long offset = FW_HEADER_SIZE + FW_NUM_ENTRIES * sizeof(fw_raw_entry);
  fw_raw_entry raw_entry;

  fseek(f, FW_HEADER_SIZE, SEEK_SET);
  for (int i = 0; i < FW_NUM_ENTRIES; i++) {
    if (fread(&raw_entry, 1, sizeof(fw_raw_entry), f) != sizeof(fw_raw_entry)) {
      return false;
    }

    if (memcmp(raw_entry.name, name, sizeof(raw_entry.name)) == 0) {
      entry->offset = offset;
      entry->size = raw_entry.size;
      entry->crc = raw_entry.crc;
      memcpy(entry->name, raw_entry.name, sizeof(raw_entry.name));
      entry->name[sizeof(raw_entry.name)] = 0;

      return true;
    }
    offset += raw_entry.size + sizeof(raw_entry.name);
  }
  return false;
}

int main(int argc, char *argv[]) {
  FILE *in_file, *out_file;
  uint8_t *compressed_chunk = NULL, *output_chunk;
  fw_entry entry;
  char section_name[6];
  size_t read_bytes, output_size;

  if (argc < 3) {
    printf("Usage: %s <input_file> <output_file>\n", argv[0]);
    return 1;
  }

  in_file = fopen(argv[1], "rb");
  if (in_file == NULL) {
    printf("Cannot open input file\n");
    return 0;
  }

  if (!get_firmware_entry(in_file, "A00000", &entry)) {
    printf("Cannot find firmware code.\n");
    return 1;
  }

  fseek(in_file, entry.offset, SEEK_SET);
  if (fread(section_name, 1, FW_ENTRY_NAME_SIZE, in_file) !=
          FW_ENTRY_NAME_SIZE ||
      memcmp(section_name, "A00000", FW_ENTRY_NAME_SIZE) != 0) {
    fprintf(stderr, "Invalid section header.\n");
    return 1;
  }

  out_file = fopen(argv[2], "wb");
  if (out_file == NULL) {
    printf("Cannot open output_chunk file\n");
    return 0;
  }

  lzp_init();

  read_bytes = 0;
  output_chunk = (unsigned char *)malloc(LZP_CHUNK_SIZE);
  if (output_chunk == NULL) {
    fprintf(stderr, "Memory error\n");
    return 1;
  }
  while (read_bytes < entry.size) {
    uint32_t compressed_size;

    if (fread(&compressed_size, sizeof(uint32_t), 1, in_file) != 1)
      break;

    compressed_chunk = realloc(compressed_chunk, compressed_size);
    if (fread(compressed_chunk, 1, compressed_size, in_file) !=
        compressed_size) {
      break;
    }
    output_size = lzp_unpack(compressed_chunk + 2, compressed_size - 2,
                             output_chunk, LZP_CHUNK_SIZE);

    fwrite(output_chunk, 1, output_size, out_file);

    read_bytes += compressed_size + sizeof(uint32_t);
  }

  if (read_bytes == entry.size) {
    printf("Firmware successfully unpacked\n");
  } else {
    printf("Error occurred during decompression\n");
  }
  free(compressed_chunk);
  lzp_destroy();

  fclose(in_file);
  fclose(out_file);
  return 0;
}
