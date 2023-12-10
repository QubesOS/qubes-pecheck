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

struct SharedNtHeader {
   uint32_t          Signature;
   EFI_IMAGE_FILE_HEADER FileHeader;
   uint16_t          Magic;
   uint8_t           MajorLinkerVersion;
   uint8_t           MinorLinkerVersion;
   uint32_t          SizeOfCode;
} __attribute__((__may_alias__));
static_assert(sizeof(struct SharedNtHeader) == 32, "bad size of struct SharedNtHeader");

union PeHeader {
   struct SharedNtHeader shared;
   EFI_IMAGE_NT_HEADERS32    pe32;
   EFI_IMAGE_NT_HEADERS64    pe32p;
} __attribute__((__may_alias__));

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

static const uint32_t pe_section_reserved_bits = 0xF6517;
static const uint32_t pe_section_code = 0x20;
static const uint32_t pe_section_initialized_data = 0x40;
static const uint32_t pe_section_uninitialized_data = 0x80;

bool pe_parse(const uint8_t *const ptr, size_t const len, struct ParsedImage *image);

#define LOG(a, ...) (fprintf(stderr, a "\n", ## __VA_ARGS__))

