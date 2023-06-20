#include <stdalign.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <err.h>
#include <unistd.h>

#include "winpe.h"
static_assert(sizeof(IMAGE_SECTION_HEADER) == 8 + 4 * 6 + 2 * 2 + 4,
              "IMAGE_SECTION_HEADER has padding?");


#define OPTIONAL_HEADER_OFFSET32 (offsetof(IMAGE_NT_HEADERS32, OptionalHeader))
#define OPTIONAL_HEADER_OFFSET64 (offsetof(IMAGE_NT_HEADERS64, OptionalHeader))

static_assert(OPTIONAL_HEADER_OFFSET32 == sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER), "unexpected padding");
static_assert(OPTIONAL_HEADER_OFFSET64 == sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER), "IMAGE_NT_HEADERS32 and IMAGE_NT_HEADERS64 must not have padding");
static_assert(alignof(IMAGE_FILE_HEADER) == 4,
              "wrong defintion of IMAGE_FILE_HEADER");
static_assert(alignof(IMAGE_NT_HEADERS32) == 4,
              "wrong defintion of IMAGE_NT_HEADERS32");
static_assert(alignof(IMAGE_NT_HEADERS64) == 8,
              "wrong defintion of IMAGE_NT_HEADERS64");
static_assert(offsetof(IMAGE_NT_HEADERS32, FileHeader) == 4,
              "wrong definition of IMAGE_NT_HEADERS32");
static_assert(offsetof(IMAGE_NT_HEADERS64, FileHeader) == 4,
              "wrong definition of IMAGE_NT_HEADERS64");
static_assert(OPTIONAL_HEADER_OFFSET64 == 24, "wrong offset of optional header");

#define LOG(a, ...) (fprintf(stderr, a "\n", ## __VA_ARGS__))

#define MIN_FILE_ALIGNMENT (UINT32_C(512))
#define MIN_OPTIONAL_HEADER_SIZE (OPTIONAL_HEADER_OFFSET32 + offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory))
#define MAX_OPTIONAL_HEADER_SIZE (sizeof(IMAGE_OPTIONAL_HEADER64))

static bool
validate_image_base_and_alignment(uint64_t const image_base,
                                  uint32_t const file_alignment,
                                  uint32_t const section_alignment)
{
   if (image_base % (1UL << 16)) {
      LOG("Image base 0x%" PRIx64 " not multiple of 0x%x", image_base, 1U << 16);
      return false;
   }
   if (section_alignment < (1U << 12)) {
      LOG("Section alignment too small (0x%" PRIx32 " < 0x%x)", section_alignment, 1U << 12);
      return false;
   }
   /*
    * The specification requires 512, but the Xen PE loader has 32 here,
    * and 32 is enough for all the casts to be well-defined.
    */
   if (file_alignment < 32) {
      LOG("File alignment too small (0x%" PRIx32 " < 0x%x)", file_alignment, 32);
      return false;
   }
   if (file_alignment > (1U << 16)) {
      LOG("Too large file alignment (0x%" PRIx32 " > 0x%x)", file_alignment, 1U << 16);
      return false;
   }
   if (file_alignment & (file_alignment - 1)) {
      LOG("Non-power of 2 file alignment 0x%" PRIx32, file_alignment);
      return false;
   }
   if (section_alignment < file_alignment) {
      LOG("File alignment greater than section alignment (0x%" PRIx32 " > 0x%" PRIx32 ")",
          file_alignment, section_alignment);
      return false;
   }
   if (section_alignment & (section_alignment - 1)) {
      LOG("Non-power of 2 section alignment 0x%" PRIx32, section_alignment);
      return false;
   }
   if (image_base & (section_alignment - 1)) {
      LOG("Image base 0x%" PRIx64 " not multiple of section alignment 0x%" PRIx32,
          image_base, section_alignment);
      return false;
   }

   return true;
}

/**
 * Extract the NT header, skipping over any DOS header.
 *
 * \return The pointer on success, or NUL on failure.
 */
static const union PeHeader*
extract_pe_header(const uint8_t *const ptr, size_t const len)
{
   static_assert(sizeof(struct IMAGE_DOS_HEADER) < sizeof(IMAGE_NT_HEADERS64),
                 "NT header shorter than DOS header?");
   static_assert(sizeof(struct IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) <= MIN_FILE_ALIGNMENT,
                 "headers too long");

   if (len > 0x7FFFFFFFUL) {
      LOG("Too long (max length 0x7FFFFFFF, got 0x%zx)", len);
      return NULL;
   }

   if (len < MIN_FILE_ALIGNMENT) {
      LOG("Too short (min length 512, got %zu)", len);
      return NULL;
   }

   if ((uintptr_t)ptr & 7) {
      LOG("Pointer %p isn't 8-byte aligned", (const void*)ptr);
      return NULL;
   }

   union PeHeader const* retval;
   if (ptr[0] == 'M' && ptr[1] == 'Z') {
      /* Skip past DOS header */
      uint32_t const nt_header_offset = ((const struct IMAGE_DOS_HEADER *)ptr)->e_lfanew;

      if (nt_header_offset < sizeof(struct IMAGE_DOS_HEADER)) {
         LOG("DOS header overlaps NT header (%" PRIi32 " less than %zu)",
             nt_header_offset, sizeof(struct IMAGE_DOS_HEADER));
         return NULL;
      }

      if (nt_header_offset > len - MIN_FILE_ALIGNMENT) {
         LOG("NT header does not leave room for section (offset %" PRIi32 ", file size %zu)",
             nt_header_offset, len);
         return NULL;
      }

      if (nt_header_offset & 7) {
         LOG("NT header not 8-byte aligned (offset %" PRIi32 ")", nt_header_offset);
         return NULL;
      }

      retval = (const union PeHeader *)(ptr + nt_header_offset);
   } else {
      retval = (const union PeHeader *)ptr;
   }

   if (memcmp(retval, "PE\0", 4) != 0) {
      LOG("Bad magic for NT header");
      return NULL;
   }

   return retval;
}

static bool parse_data(const uint8_t *const ptr, size_t const len, struct ParsedImage *image)
{
   union PeHeader const *const untrusted_pe_header = extract_pe_header(ptr, len);
   if (untrusted_pe_header == NULL)
      return NULL;

   uint32_t const nt_header_offset = (uint32_t)((uint8_t const *)untrusted_pe_header - ptr);
   uint32_t const nt_len = (uint32_t)len - nt_header_offset;
   const IMAGE_FILE_HEADER *untrusted_file_header = &untrusted_pe_header->shared.FileHeader;
#if 0
   if (!(untrusted_file_header->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
      LOG("File is not executable");
      return false;
   }
   if (untrusted_file_header->Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
      LOG("DLL cannot be executable");
      return false;
   }
   if (untrusted_file_header->Characteristics & IMAGE_FILE_DLL) {
      LOG("DLL cannot be executable");
      return false;
   }
#endif
   if (untrusted_file_header->PointerToSymbolTable ||
       untrusted_file_header->NumberOfSymbols) {
      LOG("COFF symbol tables detected");
   }

   /* sanitize SizeOfOptionalHeader start */
   if (untrusted_file_header->SizeOfOptionalHeader < MIN_OPTIONAL_HEADER_SIZE) {
      LOG("Optional header too short: got %" PRIu32 " but minimum is %zu",
          untrusted_file_header->SizeOfOptionalHeader, MIN_OPTIONAL_HEADER_SIZE);
      return false;
   }
   if (untrusted_file_header->SizeOfOptionalHeader > MAX_OPTIONAL_HEADER_SIZE) {
      LOG("Optional header too long: got %" PRIu32 " but maximum is %zu",
          untrusted_file_header->SizeOfOptionalHeader, MAX_OPTIONAL_HEADER_SIZE);
      return false;
   }
   if (untrusted_file_header->SizeOfOptionalHeader & 7) {
      LOG("Optional header size 0x%" PRIx16 " not multiple of 8",
          untrusted_file_header->SizeOfOptionalHeader);
      return false;
   }
   uint32_t const optional_header_size = untrusted_file_header->SizeOfOptionalHeader;
   /* sanitize SizeOfOptionalHeader end */

   if (untrusted_file_header->NumberOfSections < 1) {
      LOG("No sections!");
      return false;
   }

   if (untrusted_file_header->NumberOfSections > 96) {
      LOG("Too many sections: got %" PRIu16 ", limit 96", untrusted_file_header->NumberOfSections);
      return false;
   }
   uint16_t const number_of_sections = untrusted_file_header->NumberOfSections;
   /* Overflow is impossible because number_of_sections is 16-bit */
   uint32_t const section_headers_size = (uint32_t)number_of_sections * (uint32_t)sizeof(IMAGE_SECTION_HEADER);
   /*
    * Overflow is impossible because section_headers_size is limited to
    * 65535 * sizeof(IMAGE_SECTION_HEADER) and optional_header_size is limited
    * to sizeof(IMAGE_OPTIONAL_HEADER64) + IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY).
    */
   uint32_t const nt_header_size = section_headers_size + (uint32_t)OPTIONAL_HEADER_OFFSET32 + optional_header_size;
   if (nt_len <= nt_header_size) {
      LOG("Section headers do not fit in image");
      return false;
   }
   /*
    * Overflow is impossible because nt_header_size is less than nt_len,
    * and nt_len + nt_header_offset is equal to len.
    */
   uint32_t const nt_header_end = nt_header_size + nt_header_offset;

   uint64_t untrusted_image_base;
   uint32_t untrusted_file_alignment;
   uint32_t untrusted_section_alignment;
   uint32_t untrusted_size_of_headers;
   uint32_t untrusted_number_of_directory_entries;
   uint32_t min_size_of_optional_header;

   if (untrusted_pe_header->shared.Magic == 0x10b) {
      LOG("This is a PE32 file: magic 0x10b");
      static_assert(offsetof(IMAGE_NT_HEADERS32, OptionalHeader) == 24, "wrong offset");
      static_assert(offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) == 96,
                    "wrong size");
      min_size_of_optional_header = offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
      untrusted_image_base = untrusted_pe_header->pe32.OptionalHeader.ImageBase;
      untrusted_file_alignment = untrusted_pe_header->pe32.OptionalHeader.FileAlignment;
      untrusted_section_alignment = untrusted_pe_header->pe32.OptionalHeader.SectionAlignment;
      untrusted_size_of_headers = untrusted_pe_header->pe32.OptionalHeader.SizeOfHeaders;
      untrusted_number_of_directory_entries = untrusted_pe_header->pe32.OptionalHeader.NumberOfRvaAndSizes;
   } else if (untrusted_pe_header->shared.Magic == 0x20b) {
      LOG("This is a PE32+ file: magic 0x20b");
      static_assert(offsetof(IMAGE_NT_HEADERS64, OptionalHeader) == 24, "wrong offset");
      static_assert(offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) == 112,
                    "wrong size");
      min_size_of_optional_header = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
      untrusted_image_base = untrusted_pe_header->pe32p.OptionalHeader.ImageBase;
      untrusted_file_alignment = untrusted_pe_header->pe32p.OptionalHeader.FileAlignment;
      untrusted_section_alignment = untrusted_pe_header->pe32p.OptionalHeader.SectionAlignment;
      untrusted_size_of_headers = untrusted_pe_header->pe32p.OptionalHeader.SizeOfHeaders;
      untrusted_number_of_directory_entries = untrusted_pe_header->pe32p.OptionalHeader.NumberOfRvaAndSizes;
   } else {
      LOG("Bad optional header magic %" PRIu16, untrusted_pe_header->shared.Magic);
      return false;
   }
   if (untrusted_number_of_directory_entries > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
      LOG("Too many NumberOfRvaAndSizes (got %" PRIu32 ", limit 16",
          untrusted_number_of_directory_entries);
      return false;
   }
   image->directory_entries = untrusted_number_of_directory_entries;
   if (untrusted_size_of_headers >= len) {
      LOG("No space for sections!");
      return false;
   }

   if (!validate_image_base_and_alignment(untrusted_image_base,
                                          untrusted_file_alignment,
                                          untrusted_section_alignment))
      return false;
   image->file_alignment = untrusted_file_alignment;
   image->section_alignment = untrusted_section_alignment;
   image->image_base = untrusted_image_base;
   if (untrusted_size_of_headers & (image->file_alignment - 1)) {
      LOG("Misaligned size of headers: got 0x%" PRIx32 " but alignment is 0x%" PRIx32,
          untrusted_size_of_headers, image->file_alignment);
      return false;
   }
   if (untrusted_size_of_headers < nt_header_end) {
      LOG("Bad size of headers: got 0x%" PRIx32 " but first byte after section headers is 0x%" PRIx32,
          untrusted_size_of_headers, nt_header_end);
      return false;
   }
   if (untrusted_size_of_headers - nt_header_end >= image->file_alignment) {
      LOG("Too much padding after section headers: got 0x%" PRIx32 " but limit is 0x%" PRIx32,
          untrusted_size_of_headers - nt_header_end, image->file_alignment);
      return false;
   }
   image->size_of_headers = untrusted_size_of_headers;
   for (uint32_t i = nt_header_end; i < image->size_of_headers; ++i) {
      if (ptr[i]) {
         LOG("Non-zero byte at offset 0x%" PRIx32 " that should be zero", i);
         return false;
      }
   }
   uint32_t const expected_optional_header_size =
      image->directory_entries * sizeof(IMAGE_DATA_DIRECTORY) +
      min_size_of_optional_header;
   if (optional_header_size != expected_optional_header_size) {
      LOG("Wrong optional header size: got %" PRIu32 " but computed %zu",
          optional_header_size, expected_optional_header_size);
      return false;
   }
   image->directory = (const IMAGE_DATA_DIRECTORY *)
      ((const uint8_t *)untrusted_pe_header + (uint32_t)OPTIONAL_HEADER_OFFSET32 + min_size_of_optional_header);

   image->sections = (const IMAGE_SECTION_HEADER *)
      ((const uint8_t *)untrusted_pe_header + (uint32_t)OPTIONAL_HEADER_OFFSET32 + optional_header_size);
   uint32_t last_section_start = untrusted_size_of_headers;
   uint32_t last_virtual_address = 0;
   for (uint32_t i = 0; i < number_of_sections; ++i) {
      if (image->sections[i].PointerToRelocations ||
          image->sections[i].PointerToLineNumbers ||
          image->sections[i].NumberOfRelocations ||
          image->sections[i].NumberOfLineNumbers) {
         LOG("Invalid field set in image section");
         return false;
      }
      if (image->sections[i].PointerToRawData & (image->file_alignment - 1)) {
         LOG("Misaligned raw data pointer");
         return false;
      }
      if (image->sections[i].SizeOfRawData & (image->file_alignment - 1)) {
         LOG("Misaligned raw data pointer");
         return false;
      }
      if (image->sections[i].PointerToRawData != 0) {
         if (image->sections[i].PointerToRawData != last_section_start) {
            LOG("Unexpected padding: 0x%" PRIx32 " != 0x%" PRIx32,
                image->sections[i].PointerToRawData, last_section_start);
            return false;
         }
      } else {
         if (image->sections[i].SizeOfRawData != 0) {
            LOG("Section starts at zero but has nonzero size");
            return false;
         }
      }
      if (image->sections[i].VirtualAddress <= last_virtual_address) {
         LOG("Sections not sorted by VA: 0x%" PRIx32 " < 0x%" PRIx32,
             image->sections[i].VirtualAddress, last_virtual_address);
         return false;
      }
      if (len - last_section_start < image->sections[i].SizeOfRawData) {
         LOG("Section too long");
         return false;
      }
      last_section_start += image->sections[i].SizeOfRawData;
      if (UINT32_MAX - image->sections[i].VirtualAddress < image->sections[i].SizeOfRawData) {
         LOG("Virtual address overflow");
         return false;
      }
      last_virtual_address = image->sections[i].VirtualAddress;
   }

   uint32_t untrusted_signature_size = 0;
   uint32_t untrusted_signature_offset = 0;
   if (image->directory_entries >= 5) {
      untrusted_signature_offset = image->directory[4].VirtualAddress;
      untrusted_signature_size = image->directory[4].size;
   }
   if (untrusted_signature_offset == 0) {
      if (untrusted_signature_size != 0) {
         LOG("Signature offset zero but size nonzero");
         return false;
      } else {
         LOG("File is not signed");
      }
   } else {
      /* sanitize signature start */
      if (untrusted_signature_offset != last_section_start) {
         LOG("Signature does not start immediately after last section (%" PRIu32 " != %" PRIu32 ")",
               untrusted_signature_offset, last_section_start);
         return false;
      }

      if (untrusted_signature_size < sizeof(struct WIN_CERTIFICATE)) {
         LOG("Signature too small (got %" PRIu32 ", minimum 8", untrusted_signature_size);
         return false;
      }

      if (untrusted_signature_size > len - last_section_start) {
         LOG("Signature too large (got 0x%" PRIx32 "but only 0x%zu bytes left in file)",
               untrusted_signature_size, len - last_section_start);
         return false;
      }

      uint32_t const signature_offset = untrusted_signature_offset;
      uint32_t const signature_size = untrusted_signature_size;
      /* sanitize signature end */

      LOG("Signature at offset 0x%" PRIx32 " with length 0x%" PRIx32,
          signature_offset, signature_size);
      /* Alignment is guaranteed because signature_offset was checked to equal last_section_start,
       * and last_section_start must be a multiple of file_alignment.  file_alignment, in turn,
       * must be at least 512 and a power of 2.
       */
      const struct WIN_CERTIFICATE *sig = (const struct WIN_CERTIFICATE *)(ptr + signature_offset);
      if (sig->length != signature_size) {
         LOG("Size mismatch: signature is %" PRIu32 " bytes but expected %" PRIu32,
             sig->length, signature_size);
         return false;
      }
      if (sig->revision != 0x0100) {
         LOG("Wrong signature version %" PRIu16, sig->revision);
         return false;
      }
   }
   return true;
}

int main(int argc, char **argv)
{
   if (argc < 0)
      abort();
   if (argc != 2) {
      LOG("Bad number of arguments: expected 1 but got %d", argc - 1);
      return EXIT_FAILURE;
   }
   int p = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOCTTY);
   struct stat buf;
   if (fstat(p, &buf))
      err(EXIT_FAILURE, "fstat(%s)", argv[1]);
   if (buf.st_size > 0x7FFFFFFFL || buf.st_size < 0)
      errx(EXIT_FAILURE, "file %s too long", argv[1]);
   size_t size = (size_t)buf.st_size;
   uint8_t *fbuf = malloc(size);
   if (!fbuf)
      err(1, "malloc(%zu)", size);
   if ((size_t)read(p, fbuf, size) != size)
      err(1, "read()");
   struct ParsedImage image;
   if (!parse_data(fbuf, size, &image))
      errx(1, "bad PE file");
   if (fflush(NULL) || ferror(stdout) || ferror(stderr))
      errx(1, "I/O error");
   free(fbuf);
   close(p);
}
