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

#define MIN_FILE_ALIGNMENT (UINT32_C(32))
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
   if (file_alignment < MIN_FILE_ALIGNMENT) {
      LOG("File alignment too small (0x%" PRIx32 " < 0x%x)", file_alignment, MIN_FILE_ALIGNMENT);
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
   union PeHeader const* retval;
   static_assert(sizeof(struct IMAGE_DOS_HEADER) < sizeof(*retval),
                 "NT header shorter than DOS header?");
   static_assert(sizeof(struct IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) <= 512,
                 "headers too long");

   if (len > 0x7FFFFFFFUL) {
      LOG("Too long (max length 0x7FFFFFFF, got 0x%zx)", len);
      return NULL;
   }

   if (len < sizeof(*retval)) {
      LOG("Too short (min length %zu, got %zu)", sizeof(*retval), len);
      return NULL;
   }

   if ((uintptr_t)(const void *)ptr & 7) {
      LOG("Pointer %p isn't 8-byte aligned", (const void*)ptr);
      return NULL;
   }

   if (ptr[0] == 'M' && ptr[1] == 'Z') {
      /* Skip past DOS header */
      uint32_t const nt_header_offset = ((const struct IMAGE_DOS_HEADER *)ptr)->e_lfanew;

      if (nt_header_offset < sizeof(struct IMAGE_DOS_HEADER)) {
         LOG("DOS header overlaps NT header (%" PRIi32 " less than %zu)",
             nt_header_offset, sizeof(struct IMAGE_DOS_HEADER));
         return NULL;
      }

      if (nt_header_offset > len - sizeof(*retval)) {
         LOG("NT header does not leave room for section (offset %" PRIi32 ", file size %zu)",
             nt_header_offset, len);
         return NULL;
      }

      if (nt_header_offset & 7) {
         LOG("NT header not 8-byte aligned (offset %" PRIi32 ")", nt_header_offset);
         return NULL;
      }

      LOG("Skipping DOS header of %" PRIu32 " bytes", nt_header_offset);
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

static bool
validate_section_name(const IMAGE_SECTION_HEADER *section)
{
   /* Validate section name */
   const uint8_t *name = section->Name;
   if (name[0] != '.')
      LOG("Section name does not start with a \".\" - is it overlong?");
   for (uint8_t j = 0; j < sizeof(section->Name); ++j) {
      if (name[j] == '\0') {
         if (j < 1) {
            LOG("Empty section name not allowed");
            return false;
         }
         for (uint8_t k = j + 1; k < sizeof(section->Name); ++k) {
            if (name[k] != '\0') {
               LOG("Section name has NUL byte after non-NUL byte");
               return false;
            }
         }
         return true;
      }
      if (name[j] == '$') {
         LOG("$ not allowed in image section names");
         return false;
      }
      if (name[j] <= ' ' || name[j] > '~') {
         LOG("Invalid byte %" PRIu8 " in section name", name[j]);
         return false;
      }
   }
   return true;
}

static bool parse_data(const uint8_t *const ptr, size_t const len, struct ParsedImage *image)
{
   union PeHeader const *const untrusted_pe_header = extract_pe_header(ptr, len);
   if (untrusted_pe_header == NULL) {
      return false;
   }

   uint32_t const nt_header_offset = (uint32_t)((uint8_t const *)untrusted_pe_header - ptr);
   uint32_t const nt_len = (uint32_t)len - nt_header_offset;
   const IMAGE_FILE_HEADER *untrusted_file_header = &untrusted_pe_header->shared.FileHeader;
   if (!(untrusted_file_header->Characteristics & 0x2)) {
      LOG("File is not executable");
      return false;
   }
   if (untrusted_file_header->Characteristics & 0x1) {
      LOG("Relocations stripped from image");
   }
   if (untrusted_file_header->Characteristics & 0x2000) {
      LOG("DLL cannot be executable");
   }
   if (untrusted_file_header->PointerToSymbolTable ||
       untrusted_file_header->NumberOfSymbols) {
      LOG("COFF symbol tables detected: symbol table offset 0x%" PRIx32
          ", number of symbols 0x%" PRIx32,
          untrusted_file_header->PointerToSymbolTable,
          untrusted_file_header->NumberOfSymbols);
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

   /* sanitize NumberOfSections start */
   if (untrusted_file_header->NumberOfSections < 1) {
      LOG("No sections!");
      return false;
   }

   if (untrusted_file_header->NumberOfSections > 96) {
      LOG("Too many sections: got %" PRIu16 ", limit 96", untrusted_file_header->NumberOfSections);
      return false;
   }

   /*
    * Overflow is impossible because NumberOfSections is limited to 96 and
    * optional_header_size is limited to sizeof(IMAGE_OPTIONAL_HEADER64).
    * Therefore, the maximum is 40 * 96 + 112 + 16 * 8 = 4080 bytes.
    */
   uint32_t const untrusted_nt_headers_size =
      (untrusted_file_header->NumberOfSections * (uint32_t)sizeof(IMAGE_SECTION_HEADER)) +
      ((uint32_t)OPTIONAL_HEADER_OFFSET32 + optional_header_size);
   /* sanitize NT headers size start */
   if (nt_len <= untrusted_nt_headers_size) {
      LOG("Section headers do not fit in image");
      return false;
   }
   uint32_t const nt_header_size = untrusted_nt_headers_size;
   /* sanitize NT headers size end */

   /* we now know that NumberOfSections is okay */
   uint32_t const number_of_sections = untrusted_file_header->NumberOfSections;
   /* sanitize NumberOfSections end */

   image->n_sections = number_of_sections;
   image->sections = (const IMAGE_SECTION_HEADER *)
      ((const uint8_t *)untrusted_pe_header + (uint32_t)OPTIONAL_HEADER_OFFSET32 + optional_header_size);

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
   uint64_t max_address;

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
      max_address = UINT32_MAX;
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
      max_address = UINT64_MAX;
   } else if (untrusted_pe_header->shared.Magic == 0xb20 ||
              untrusted_pe_header->shared.Magic == 0xb10) {
      LOG("Optional header indicates endian-swapped file (not implemented) %" PRIu16, untrusted_pe_header->shared.Magic);
      return false;
   } else {
      LOG("Bad optional header magic %" PRIu16, untrusted_pe_header->shared.Magic);
      return false;
   }

   /* sanitize directory entry number start */
   if (untrusted_number_of_directory_entries > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
      LOG("Too many NumberOfRvaAndSizes (got %" PRIu32 ", limit 16",
          untrusted_number_of_directory_entries);
      return false;
   }
   image->directory_entries = untrusted_number_of_directory_entries;
   /* sanitize directory entry number end */

   if (!validate_image_base_and_alignment(untrusted_image_base,
                                          untrusted_file_alignment,
                                          untrusted_section_alignment))
      return false;
   image->file_alignment = untrusted_file_alignment;
   image->section_alignment = untrusted_section_alignment;
   image->image_base = untrusted_image_base;

   /* sanitize SizeOfHeaders start */
   if (untrusted_size_of_headers >= len) {
      LOG("SizeOfHeaders extends past end of image (0x%" PRIx32 " > 0x%zu)",
          untrusted_size_of_headers, len);
      return false;
   }
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
   /* sanitize SizeOfHeaders end */

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
      LOG("Wrong optional header size: got %" PRIu32 " but computed %" PRIu32,
          optional_header_size, expected_optional_header_size);
      return false;
   }
   image->directory = (const IMAGE_DATA_DIRECTORY *)
      ((const uint8_t *)untrusted_pe_header + (uint32_t)OPTIONAL_HEADER_OFFSET32 + min_size_of_optional_header);

   /* Overflow is impossible: max_address is always at least as large as image->image_base */
   uint64_t const image_address_space = max_address - image->image_base;
   uint32_t last_section_start = image->size_of_headers;
   uint64_t last_virtual_address = 0;
   uint64_t last_virtual_address_end = 0;
   const uint8_t *section_name = NULL, *new_section_name = NULL;
   for (uint32_t i = 0; i < number_of_sections; ++i) {
      if (image->sections[i].PointerToRelocations != 0 ||
          image->sections[i].NumberOfRelocations != 0) {
         LOG("Section %" PRIu32 " contains COFF relocations", i);
         return false;
      }

      if (image->sections[i].PointerToLineNumbers != 0 ||
          image->sections[i].NumberOfLineNumbers != 0) {
         LOG("Section %" PRIu32 " contains COFF line numbers", i);
         return false;
      }

      if (!validate_section_name(image->sections + i))
         return false;
      new_section_name = image->sections[i].Name;

      /* Validate PointerToRawData and SizeOfRawData */
      if (image->sections[i].PointerToRawData & (image->file_alignment - 1)) {
         LOG("Misaligned raw data pointer");
         return false;
      }
      if (image->sections[i].SizeOfRawData & (image->file_alignment - 1)) {
         LOG("Misaligned raw data size");
         return false;
      }
      if (image->sections[i].PointerToRawData != 0) {
         if (image->sections[i].PointerToRawData != last_section_start) {
            LOG("Section %" PRIu32 " starts at 0x%" PRIx32 ", but %s at 0x%" PRIx32,
                i, image->sections[i].PointerToRawData,
                i > 0 ? "previous section ends" : "NT headers end",
                last_section_start);
            return false;
         }
      } else {
         if (image->sections[i].SizeOfRawData != 0) {
            LOG("Section %" PRIu32 " starts at zero but has nonzero size", i);
            return false;
         }
      }
      if (len - last_section_start < image->sections[i].SizeOfRawData) {
         LOG("Section %" PRIu32 " too long: length is %" PRIu32 " but only %" PRIu32
             " bytes remaining in file", i,
             image->sections[i].SizeOfRawData,
             (uint32_t)(len - last_section_start));
         return false;
      }
      last_section_start += image->sections[i].SizeOfRawData;

      /* Validate VirtualAddress and VirtualSize */
      if (image->sections[i].VirtualAddress > image_address_space) {
         LOG("VMA too large: 0x%" PRIx32 " extends beyond address space [0x%" PRIx64 ", 0x%" PRIx64 "]",
             image->sections[i].VirtualAddress, image->image_base, max_address);
         return false;
      }
      uint64_t const untrusted_virtual_address = image->sections[i].VirtualAddress + image->image_base;
      if (untrusted_virtual_address & (image->section_alignment - 1)) {
         LOG("Section %" PRIu32 " (%.8s) has misaligned VMA: 0x%" PRIx64 " not aligned to 0x%" PRIx32,
             i, image->sections[i].Name, untrusted_virtual_address, image->section_alignment);
      }
      if (max_address - untrusted_virtual_address < image->sections[i].VirtualSize) {
         LOG("Virtual address overflow: 0x%" PRIx64 " + 0x%" PRIx32 " > 0x%" PRIx64,
             untrusted_virtual_address, image->sections[i].VirtualSize, max_address);
         return false;
      }
      LOG("Section %" PRIu32 "(name %.8s) has flags 0x%" PRIx32, i, new_section_name, image->sections[i].Characteristics);
      uint32_t untrusted_characteristics = image->sections[i].Characteristics;
      if ((untrusted_characteristics & pe_section_reserved_bits) != 0) {
         LOG("Section %" PRIu32 ": characteristics 0x%08" PRIx32 " has reserved bits",
             i, untrusted_characteristics);
         return false;
      }
      if ((untrusted_characteristics & (pe_section_code|pe_section_initialized_data|pe_section_uninitialized_data))) {
         if (untrusted_virtual_address < last_virtual_address) {
            assert(new_section_name != NULL);
            assert(section_name != NULL);
            LOG("Sections not sorted by VA: current section (%.8s) VA 0x%" PRIx64 " < previous section (%.8s) 0x%" PRIx64,
                new_section_name, untrusted_virtual_address, section_name, last_virtual_address);
            return false;
         }
         if (untrusted_virtual_address < last_virtual_address_end) {
            assert(new_section_name != NULL);
            assert(section_name != NULL);
            LOG("Sections %.8s (%" PRIu32 ") and %.8s (%" PRIu32 ") overlap in memory: 0x%" PRIx64 " in [0x%" PRIx64 ", 0x%" PRIx64 ")",
                section_name, i - 1, new_section_name, i, untrusted_virtual_address, last_virtual_address, last_virtual_address_end);
            return false;
         }
         last_virtual_address = untrusted_virtual_address;
         last_virtual_address_end = last_virtual_address + image->sections[i].VirtualSize;
         section_name = new_section_name;
      }

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
      if (len != last_section_start) {
         LOG("%" PRIu32 " bytes of junk after sections",
             (uint32_t)(len - last_section_start));
         return false;
      }
   } else {
      /* sanitize signature offset and size start */
      if (untrusted_signature_offset != last_section_start) {
         LOG("Signature does not start immediately after last section (%" PRIu32 " != %" PRIu32 ")",
               untrusted_signature_offset, last_section_start);
         return false;
      }

      if (untrusted_signature_size > len - last_section_start) {
         LOG("Signature too large (got 0x%" PRIx32 "but only 0x%zu bytes left in file)",
               untrusted_signature_size, len - last_section_start);
         return false;
      }

      if ((untrusted_signature_size & 7) != 0) {
         LOG("Signature size not a multiple of 8 (got 0x%" PRIx32 ")",
             untrusted_signature_size);
         return false;
      }

      uint32_t signature_offset = untrusted_signature_offset;
      uint32_t signature_size = untrusted_signature_size;
      /* sanitize signature offset and size end */

      /* Alignment is guaranteed initially because signature_offset was checked to equal
       * last_section_start, and last_section_start must be a multiple of file_alignment.
       * file_alignment, in turn, must be at least 32 and a power of 2.  Alignment will
       * be maintained because sig->length must be a multiple of 8.
       */
      do {
         if (signature_size < sizeof(struct WIN_CERTIFICATE)) {
            LOG("Signature too small (got %" PRIu32 ", minimum 8", signature_size);
            return false;
         }
         const struct WIN_CERTIFICATE *sig = (const struct WIN_CERTIFICATE *)(ptr + signature_offset);
         if (sig->revision != 0x0200) {
            LOG("Wrong signature version 0x%" PRIx16, sig->revision);
            return false;
         }
         if (sig->certificate_type != 0x0002) {
            LOG("Wrong signature type 0x%" PRIx16, sig->revision);
            return false;
         }
         if (sig->length > signature_size) {
            LOG("Signature too long: signature is 0x%" PRIx32 " bytes but directory entry has 0x%" PRIx32 " bytes",
                sig->length, signature_size);
            return false;
         }
         if (sig->length < sizeof(struct WIN_CERTIFICATE)) {
            LOG("Signature too small (got %" PRIu32 ", minimum 8", signature_size);
            return false;
         }
         if (sig->length & 7) {
            LOG("Signature length 0x%" PRIx32 " is not 8-byte aligned", sig->length);
            return false;
         }
         LOG("Signature at offset 0x%" PRIx32 " with length 0x%" PRIx32,
             signature_offset, sig->length);
         signature_offset += sig->length;
         signature_size -= sig->length;
      } while (signature_size > 0);

      if (signature_offset != len) {
         LOG("%" PRIu32 " bytes of junk after signatures",
             (uint32_t)(len - signature_offset));
         return false;
      }
   }
   return true;
}

int main(int argc, char **argv)
{
   if (argc < 0)
      abort();
   if (argc < 2) {
      LOG("Bad number of arguments: expected at least 1 but got %d", argc - 1);
      return EXIT_FAILURE;
   }
   for (int i = 1; i < argc; ++i) {
      int p = open(argv[i], O_RDONLY | O_CLOEXEC | O_NOCTTY);
      struct stat buf;
      if (fstat(p, &buf))
         err(EXIT_FAILURE, "fstat(%s)", argv[i]);
      if (buf.st_size > 0x7FFFFFFFL || buf.st_size < 0)
         errx(EXIT_FAILURE, "file %s too long", argv[i]);
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
}
