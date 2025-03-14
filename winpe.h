#include <stdint.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <uchar.h>

typedef bool BOOLEAN;
typedef uint8_t UINT8;
typedef int8_t INT8;
typedef uint16_t UINT16;
typedef int16_t INT16;
typedef uint32_t UINT32;
typedef int32_t INT32;
typedef uint64_t UINT64;
typedef int64_t INT64;
typedef uintptr_t UINTN;
typedef intptr_t INTN;
typedef signed char CHAR8;
typedef char16_t CHAR16;
#include "Base.h"
#include "PeImage.h"

struct ParsedImage {
   uint64_t image_base;
   uint32_t file_alignment;
   uint32_t section_alignment;
   EFI_IMAGE_DATA_DIRECTORY const *directory;
   EFI_IMAGE_SECTION_HEADER const *sections;
   uint32_t directory_entries;
   uint32_t n_sections;
   uint32_t size_of_headers;
   uint32_t _pad0;
};

enum {
    pe_section_reserved_bits = 0xF6D1F,
};

bool pe_parse(const uint8_t *const ptr, size_t const len, struct ParsedImage *image);

#define LOG(a, ...) (fprintf(stderr, a "\n", ## __VA_ARGS__))

