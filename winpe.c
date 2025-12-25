#include <stdalign.h>
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
#include <errno.h>
#include <limits.h>

#include "winpe.h"
#include "winpe-private.h"
#include "WinCertificate.h"
static_assert(sizeof(EFI_IMAGE_SECTION_HEADER) == 8 + 4 * 6 + 2 * 2 + 4,
              "EFI_IMAGE_SECTION_HEADER has padding?");


#define OPTIONAL_HEADER_OFFSET UINT32_C(24)

static_assert(OPTIONAL_HEADER_OFFSET == sizeof(uint32_t) + sizeof(EFI_IMAGE_FILE_HEADER), "unexpected padding");
static_assert(alignof(EFI_IMAGE_FILE_HEADER) == 4,
              "wrong defintion of EFI_IMAGE_FILE_HEADER");
static_assert(alignof(EFI_IMAGE_NT_HEADERS32) == 4,
              "wrong defintion of IMAGE_NT_HEADERS32");
static_assert(alignof(EFI_IMAGE_NT_HEADERS64) == 8,
              "wrong defintion of IMAGE_NT_HEADERS64");
static_assert(offsetof(EFI_IMAGE_NT_HEADERS32, FileHeader) == 4,
              "wrong definition of IMAGE_NT_HEADERS32");
static_assert(offsetof(EFI_IMAGE_NT_HEADERS64, FileHeader) == 4,
              "wrong definition of IMAGE_NT_HEADERS64");

#define MIN_FILE_ALIGNMENT (UINT32_C(32))
#define MAX_FILE_ALIGNMENT (UINT32_C(1) << 16)
#define MIN_OPTIONAL_HEADER_SIZE (offsetof(EFI_IMAGE_OPTIONAL_HEADER32, DataDirectory))
#define MAX_OPTIONAL_HEADER_SIZE (sizeof(EFI_IMAGE_OPTIONAL_HEADER64))

/**
 * Obtain a pointer to size bytes with alignment align at offset offset.
 *
 * Returns NULL on failure, including:
 *
 * - The number of bytes is out of bounds.
 * - The pointer produced would not be aligne.d
 * - An integer overflow occurred.
 * - The alignment is not a power of 2.
 */
static const void *extract_struct_count(const struct PeBuffer *const buffer,
                                        size_t const offset, size_t const align,
                                        size_t const size, size_t const count)
{
   assert(IS_POW2(align) && "Alignment is not a power of 2");

   size_t total_size, requested_end;
   if (__builtin_mul_overflow(size, count, &total_size)) {
       LOG("Size overflow: %zu * %zu > %zu", size, count, SIZE_MAX);
       return NULL;
   }

   if (__builtin_add_overflow(total_size, offset, &requested_end)) {
      LOG("Size overflow: %zu + %zu > %zu", total_size, offset, SIZE_MAX);
      return NULL;
   }

   if (requested_end > buffer->size) {
      LOG("Out of bounds: %zu + %zu > %zu", size, offset, buffer->size);
      return NULL;
   }

   const uint8_t *const new_ptr = buffer->ptr + offset;
   if (((uintptr_t)new_ptr & (align - 1)) != 0) {
      LOG("Returned pointer would be misaligned");
      return NULL;
   }

   return new_ptr;
}

#define STRUCT_AT(buffer, offset, ty) \
   ((const ty *)extract_struct_count(buffer, offset, _Alignof(ty), sizeof(ty), 1))

#define STRUCT_AT_COUNT(buffer, offset, ty, count) \
   ((const ty *)extract_struct_count(buffer, offset, _Alignof(ty), sizeof(ty), count))

struct dos_header {
   uint8_t padding[60];
   uint32_t nt_header_offset;
};
static_assert(sizeof(struct dos_header) == 64, "header def bug");

/**
 * Extract the NT header, skipping over any DOS header.
 *
 * If this function returns a valid pointer, the entire NT header is
 * guaranteed to be in bounds.  However, not all of it might actually be
 * valid.  Accessing invalid members (such as a nonexistent data directory)
 * will produce garbage from other parts of the PE file.  It will not
 * result in undefined behavior or a memory access violation.
 *
 * \return The pointer on success, or NULL on failure.
 */
const EFI_IMAGE_OPTIONAL_HEADER_UNION*
extract_pe_header(const struct PeBuffer b)
{
   uint32_t nt_header_offset = 0;
#define NT_HEADER_OFFSET_LOC ((uint32_t)(offsetof(EFI_IMAGE_DOS_HEADER, e_lfanew)))
   EFI_IMAGE_OPTIONAL_HEADER_UNION const* pe_header;
   static_assert(sizeof(*pe_header) >= sizeof(EFI_IMAGE_DOS_HEADER),
                 "NT header shorter than DOS header?");

   if (b.size < sizeof(*pe_header)) {
      LOG("Too short (min length %zu, got %zu)", sizeof(*pe_header), b.size);
      return NULL;
   }

   if (b.size > 0x7FFFFFFFUL) {
      LOG("Too long (max length 0x7FFFFFFF, got 0x%zx)", b.size);
      return NULL;
   }

   if (!ADDRESS_IS_ALIGNED((const void *)b.ptr, 8)) {
      LOG("Pointer %p isn't 8-byte aligned", (const void*)b.ptr);
      return NULL;
   }

   if (b.ptr[0] == 'M' && b.ptr[1] == 'Z') {
      const struct dos_header *dos_hdr = STRUCT_AT(&b, 0, struct dos_header);
      if (dos_hdr == NULL) {
         return NULL;
      }
      nt_header_offset = dos_hdr->nt_header_offset;

      if (nt_header_offset < sizeof(*dos_hdr)) {
         LOG("DOS header overlaps NT header (%" PRIu32 " less than %zu)",
             nt_header_offset, sizeof(*dos_hdr));
         return NULL;
      }

      pe_header = STRUCT_AT(&b, nt_header_offset, EFI_IMAGE_OPTIONAL_HEADER_UNION);
   } else {
      pe_header = STRUCT_AT(&b, 0, EFI_IMAGE_OPTIONAL_HEADER_UNION);
   }
   if (pe_header == NULL) {
      return NULL;
   }

   if (memcmp(pe_header, "PE\0", 4) != 0) {
      LOG("Bad magic for NT header at offset 0x%" PRIx32, nt_header_offset);
      return NULL;
   }

   return pe_header;
}

static const char *
string_table_lookup(const struct ParsedImage *image, uint64_t offset)
{
   if (offset >= image->string_table_size)
      return NULL;
   assert(image->string_table);
   if (offset < 4)
      return "";
   return image->string_table + offset;
}

static const char *
get_section_name(const EFI_IMAGE_SECTION_HEADER *section, const struct ParsedImage *image, int *len)
{
   static_assert(INT_MAX == 0x7FFFFFFFUL, "whoops");
   /* Validate section name */
   const uint8_t *name = section->Name;
   uint32_t j;
   size_t section_name_len = sizeof(section->Name);
   *len = 0;
   bool in_string_table = name[0] == '/';
   if (in_string_table) {
      // Copy to ensure NUL termination
      char tmpbuf[sizeof(section->Name)] = {0};
      memcpy(tmpbuf, name + 1, sizeof(tmpbuf) - 1);
      if (tmpbuf[0] < '0' || tmpbuf[0] > '9') {
         LOG("Invalid string table offset");
         return false;
      }
      if (tmpbuf[0] == '0' && tmpbuf[1] != '\0') {
         LOG("Spurious leading zero in string table offset");
         return false;
      }
      char *end;
      errno = 0;
      unsigned long r = strtoul(tmpbuf, &end, 10);
      if (errno != 0) {
         LOG("Error getting string table offset");
         return false;
      }
      for (const char *p = end; p < tmpbuf + sizeof(tmpbuf) - 1; p++) {
         if (*p) {
            LOG("String table index has non-NULL byte after string table "
                "index");
            return false;
         }
      }
      name = (const uint8_t *)string_table_lookup(image, r);
      if (name == NULL) {
         LOG("String table index %lu is out of bounds for string table", r);
         return false;
      }
      section_name_len = strlen((const char *)name);
      if (section_name_len <= sizeof(section->Name)) {
         LOG("Toolchain used string table for section name of length %zu "
             "bytes, but section names of length 8 or less don't need it",
             section_name_len);
         return false;
      }
   }
   for (j = 0; j < section_name_len; ++j) {
      if (name[j] == '\0')
         break;
      if (name[j] == '$') {
         LOG("$ not allowed in image section names");
         return false;
      }
      if (!((name[j] >= 'a' && name[j] <= 'z') ||
            (name[j] >= 'A' && name[j] <= 'Z') ||
            (name[j] >= '0' && name[j] <= '9') ||
            (name[j] == '.') || (name[j] == '-') ||
            (name[j] == '_'))) {
         LOG("Invalid byte %" PRIu8 " in section name", name[j]);
         return false;
      }
   }
   for (uint8_t k = j; k < sizeof(section->Name); ++k) {
      if (name[k] != '\0') {
         LOG("Section name has non-NUL byte after NUL byte");
         return false;
      }
   }
   *len = (int)j;
   assert(*len > 0 && (size_t)*len == j);
   return (const char *)name;
}

#define MAX_IN_MEMORY_ALIGNMENT (1UL << 16)
#define MIN_SECTION_ALIGNMENT (1UL << 12)
#define MAX_SECTION_ALIGNMENT (1UL << 16)
#define MIN_BASE_ALIGNMENT (1UL << 16)
static bool
validate_image_base_and_alignment(uint64_t const image_base,
                                  uint32_t const file_alignment,
                                  uint32_t const section_alignment)
{
   if (image_base % MIN_BASE_ALIGNMENT) {
      LOG("Image base 0x%" PRIx64 " not multiple of 0x%lx", image_base,
          MIN_BASE_ALIGNMENT);
      return false;
   }
   // Sections must be at least PAGE_SIZE aligned.
   if (section_alignment < MIN_SECTION_ALIGNMENT) {
      LOG("Section alignment too small (0x%" PRIx32 " < 0x%lx)", section_alignment,
          MIN_SECTION_ALIGNMENT);
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
   // The PE specification limits file alignments to 1 << 16.
   if (file_alignment > MAX_FILE_ALIGNMENT) {
      LOG("Too large file alignment (0x%" PRIx32 " > 0x%x)",
          file_alignment, MAX_FILE_ALIGNMENT);
      return false;
   }
   if (!IS_POW2(file_alignment)) {
      LOG("Non-power of 2 file alignment 0x%" PRIx32, file_alignment);
      return false;
   }
   if (section_alignment < file_alignment) {
      LOG("File alignment greater than section alignment (0x%" PRIx32 " > 0x%" PRIx32 ")",
          file_alignment, section_alignment);
      return false;
   }
   if (!IS_POW2(section_alignment)) {
      LOG("Non-power of 2 section alignment 0x%" PRIx32, section_alignment);
      return false;
   }
   if (!IS_ALIGNED(image_base, section_alignment)) {
      LOG("Image base 0x%" PRIx64 " not multiple of section alignment 0x%" PRIx32,
          image_base, section_alignment);
      return false;
   }

   return true;
}

static bool
validate_data_directories(const EFI_IMAGE_DATA_DIRECTORY *const directory,
                          uint32_t const directory_entries)
{
   for (uint32_t i = 0; i < directory_entries; ++i) {
      uint32_t const virtual_address = directory[i].VirtualAddress;
      uint32_t const size =  directory[i].Size;
      if (UINT32_MAX - virtual_address < size) {
         LOG("Data directory %" PRIu32 " is invalid: 0x%" PRIx32 " + 0x%" PRIx32 " > UINT32_MAX",
             i, virtual_address, size);
         return false;
      }

      if (virtual_address == 0 && size != 0) {
         LOG("Data directory %" PRIu32 " is invalid: virtual address is 0 but size is 0x%" PRIx32,
             i, size);
         return false;
      }
   }

   return true;
}

/**
 * Check if the given directory fits in the given section.
 */
static bool
directory_in_section(EFI_IMAGE_DATA_DIRECTORY const directory,
                     EFI_IMAGE_SECTION_HEADER const *const section_header,
                     bool *found, uint32_t directory_index, uint32_t section_index)
{
   // End of directory in address space.
   // Overflow is not possible: checked by parse_optional_header.
   uint32_t const directory_end = directory.VirtualAddress + directory.Size;

   // End of section in address space.
   // Overflow is not possible: checked by pe_parse.
   uint32_t const section_end = section_header->Misc.VirtualSize + section_header->VirtualAddress;

   if (section_header->VirtualAddress < directory_end &&
       directory.VirtualAddress < section_end) {
      if (section_header->PointerToRawData == 0) {
         LOG("Data directory is located in an unmapped section");
         return false;
      }

      if (directory.VirtualAddress < section_header->VirtualAddress) {
         LOG("Directory starts before section");
         return false;
      }

      if (section_end < directory_end) {
         LOG("Directory %" PRIu32 " extends past section %" PRIu32
             ": directory is [0x%" PRIx32 ", 0x%" PRIx32 ") but section is [0x%" PRIx32 ", 0x%" PRIx32 ")",
             directory_index, section_index,
             directory.VirtualAddress, directory_end,
             section_header->VirtualAddress, section_end);
         return false;
      }

      if ((section_header->Characteristics & (EFI_IMAGE_SCN_CNT_CODE|EFI_IMAGE_SCN_CNT_INITIALIZED_DATA)) == 0) {
          LOG("Directory %" PRIu32 " is in section that is not loaded into memory",
              directory_index);
          return false;
      }

      if (found != NULL)
         *found = true;
   }

   return true;
}

bool signature_section_check(const uint8_t *const signature, size_t const len, bool const verbose)
{
   if (!ADDRESS_IS_ALIGNED(signature, 8) || len > (size_t)(INT32_MAX & ~7))
      return false;

   if (!IS_ALIGNED(len, 8)) {
      LOG("Signature size not a multiple of 8 (got 0x%zx)", len);
      return false;
   }

   uint64_t const zero = 0;
   const uint8_t *current_pointer = signature;
   const uint8_t *const end = signature + len;
   do {
      WIN_CERTIFICATE sig;
      if (end - current_pointer < (ptrdiff_t)sizeof(sig)) {
         LOG("Signature too small (got 0x%zx, minimum 8", (size_t)(end - current_pointer));
         return false;
      }
      const size_t remaining_bytes = (size_t)(end - current_pointer);
      assert(IS_ALIGNED(remaining_bytes, 8) && "remaining bytes not multiple of 8!");
      memcpy(&sig, current_pointer, sizeof(sig));
      if (sig.wRevision != 0x0200) {
         LOG("Wrong signature version 0x%" PRIx16, sig.wRevision);
         return false;
      }
      if (sig.wCertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
         LOG("Wrong signature type 0x%" PRIx16, sig.wCertificateType);
         return false;
      }
      if (sig.dwLength > remaining_bytes) {
         LOG("Signature too long: signature is 0x%" PRIx32 " bytes but 0x%zx bytes remaining in signature",
               sig.dwLength, remaining_bytes);
         return false;
      }
      if (sig.dwLength < sizeof(sig)) {
         LOG("Signature too small (got %" PRIu32 ", minimum %zu)", sig.dwLength, sizeof(sig));
         return false;
      }
      if (verbose)
         LOG("Signature at offset 0x%zx with length 0x%" PRIx32,
             (size_t)(current_pointer - signature), sig.dwLength);
      // remaining_bytes is always a multiple of 8, so this is still in bounds.
      uint32_t new_length = (sig.dwLength + UINT32_C(7)) & ~UINT32_C(7);
      if (memcmp(&zero, current_pointer + sig.dwLength, new_length - sig.dwLength) != 0) {
         LOG("Padding in WIN_CERTIFICATE struct is not zeroed");
         return false;
      }
      current_pointer += new_length;
   } while (end > current_pointer);
   return true;
}

static bool
parse_headers(struct PeBuffer full, bool verbose, struct ParsedImage *image, bool strict)
{
   uint32_t untrusted_size_of_headers;
   uint32_t untrusted_data_directory_count;
   size_t data_directory_offset;
   uint64_t untrusted_image_base;
   uint32_t untrusted_file_alignment;
   uint32_t untrusted_section_alignment;

   EFI_IMAGE_OPTIONAL_HEADER_UNION const *const untrusted_pe_header = extract_pe_header(full);
   if (untrusted_pe_header == NULL) {
      return false;
   }
   uint32_t const nt_header_offset = (uint32_t)((uint8_t const *)untrusted_pe_header - full.ptr);
   const EFI_IMAGE_FILE_HEADER *const untrusted_file_header = &untrusted_pe_header->Pe32.FileHeader;

   switch (untrusted_pe_header->Pe32.OptionalHeader.Magic) {
   case EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC:
      if (verbose)
         LOG("This is a PE32+ file: magic 0x20b");
      data_directory_offset = offsetof(EFI_IMAGE_OPTIONAL_HEADER64, DataDirectory);
      image->directory = untrusted_pe_header->Pe32Plus.OptionalHeader.DataDirectory;
      untrusted_data_directory_count =
         untrusted_pe_header->Pe32Plus.OptionalHeader.NumberOfRvaAndSizes;
      untrusted_file_alignment = untrusted_pe_header->Pe32Plus.OptionalHeader.FileAlignment;
      untrusted_image_base = untrusted_pe_header->Pe32Plus.OptionalHeader.ImageBase;
      untrusted_section_alignment = untrusted_pe_header->Pe32Plus.OptionalHeader.SectionAlignment;
      untrusted_size_of_headers = untrusted_pe_header->Pe32Plus.OptionalHeader.SizeOfHeaders;
      image->max_address = UINT64_MAX;
      break;
   case EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
      if (verbose)
         LOG("This is a PE32 file: magic 0x10b");
      data_directory_offset = offsetof(EFI_IMAGE_OPTIONAL_HEADER32, DataDirectory);
      image->directory = untrusted_pe_header->Pe32.OptionalHeader.DataDirectory;
      untrusted_data_directory_count = untrusted_pe_header->Pe32.OptionalHeader.NumberOfRvaAndSizes;
      untrusted_file_alignment = untrusted_pe_header->Pe32.OptionalHeader.FileAlignment;
      untrusted_image_base = untrusted_pe_header->Pe32.OptionalHeader.ImageBase;
      untrusted_section_alignment = untrusted_pe_header->Pe32.OptionalHeader.SectionAlignment;
      untrusted_size_of_headers = untrusted_pe_header->Pe32.OptionalHeader.SizeOfHeaders;
      image->max_address = UINT32_MAX;
      break;
   default:
      LOG("Image magic is %" PRIu16 ", which is not valid for 32-bit or 64-bit PE file",
          untrusted_pe_header->Pe32.OptionalHeader.Magic);
      return false;
   }
   if (untrusted_size_of_headers > full.size) {
      LOG("Headers do not fit in image: headers %" PRIu32 ", image %zu", untrusted_size_of_headers,
          full.size);
      return false;
   }
   /* sanitize size of headers end */
   image->size_of_headers = untrusted_size_of_headers;
   struct PeBuffer headers = {.ptr = full.ptr, .size = untrusted_size_of_headers};

   if (untrusted_data_directory_count > EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES) {
      LOG("Image has %" PRIu32 " data directories, but limit is 16",
          untrusted_data_directory_count);
      return false;
   }
   image->directory_entries = untrusted_data_directory_count;
   /* sanitize data directory count end */

   /* sanitize size of optional header start */
   size_t optional_header_size =
      data_directory_offset + image->directory_entries * sizeof(EFI_IMAGE_DATA_DIRECTORY);
   if (optional_header_size != untrusted_file_header->SizeOfOptionalHeader) {
      LOG("Size of optional header is wrong: expected %zu, but got %" PRIu16, optional_header_size,
          untrusted_file_header->SizeOfOptionalHeader);
      return false;
   }
   /* sanitize size of optional header end */

   /* sanitize number of sections start */
   if (untrusted_file_header->NumberOfSections < 1) {
      LOG("No sections!");
      return false;
   }
   // Wraparound is impossible because nt_header_offset is checked to fit in
   // 2GiB and header size is bounded by sizeof(EFI_IMAGE_OPTIONAL_HEADER_UNION)
   uint32_t section_header_start =
      nt_header_offset + optional_header_size + offsetof(EFI_IMAGE_NT_HEADERS64, OptionalHeader);

   image->sections = STRUCT_AT_COUNT(&headers, section_header_start, EFI_IMAGE_SECTION_HEADER,
                                     untrusted_file_header->NumberOfSections);
   if (image->sections == NULL) {
      LOG("Section headers do not fit in headers");
      return false;
   }
   /* santize number of sections end */
   image->n_sections = untrusted_file_header->NumberOfSections;
   // No bounds check on untrusted_image_base is needed,
   // as PE32 images only use a 4-byte field for it.
   // Therefore, values above max_address simply are not expressable.
   if (!validate_image_base_and_alignment(untrusted_image_base, untrusted_file_alignment,
                                          untrusted_section_alignment))
      return false;
   if (!IS_ALIGNED(headers.size, untrusted_file_alignment)) {
      LOG("Misaligned size of headers: got 0x%zu but alignment is 0x%" PRIx32, headers.size,
          image->file_alignment);
      return false;
   }

   if (!(untrusted_pe_header->Pe32.FileHeader.Characteristics & EFI_IMAGE_FILE_EXECUTABLE_IMAGE)) {
      LOG("File is not executable");
      return false;
   }
   if (untrusted_pe_header->Pe32.FileHeader.Characteristics & EFI_IMAGE_FILE_RELOCS_STRIPPED) {
      LOG("Relocations stripped from image.  The image can only be loaded at its base address");
      if (strict)
         return false;
   }
   if (untrusted_pe_header->Pe32.FileHeader.Characteristics & EFI_IMAGE_FILE_DLL) {
      LOG("DLLs are not executable directly");
      // This is a valid PE image, so only reject it in strict mode.
      if (strict)
         return false;
   }
   image->file_alignment = untrusted_file_alignment;
   image->section_alignment = untrusted_section_alignment;
   image->image_base = untrusted_image_base;
   image->characteristics = untrusted_pe_header->Pe32.FileHeader.Characteristics;

   uint32_t untrusted_pointer_to_symbol_table =
      untrusted_pe_header->Pe32.FileHeader.PointerToSymbolTable;
   uint32_t untrusted_number_of_symbols = untrusted_pe_header->Pe32.FileHeader.NumberOfSymbols;
   uint32_t string_table_size;

   if (untrusted_pointer_to_symbol_table == 0) {
      if (untrusted_number_of_symbols != 0) {
         LOG("Symbol table nonempty but at offset 0");
         return false;
      }
      image->string_table = NULL;
      image->string_table_size = 0;
   } else {
      if (untrusted_pointer_to_symbol_table < image->size_of_headers) {
         LOG("Symbol table is at offset 0x%" PRIx32 ", overlapping headers that end at 0x%" PRIx32,
             untrusted_pointer_to_symbol_table, image->size_of_headers);
         return false;
      }
      // cannot wrap because UINT32_MAX * UINT32_MAX + UINT32_MAX + UINT32_MAX
      // == UINT64_MAX
      uint64_t untrusted_strings_start =
         (uint64_t)untrusted_number_of_symbols * (uint64_t)EFI_IMAGE_SIZEOF_SYMBOL +
         (uint64_t)untrusted_pointer_to_symbol_table;
      // cannot wrap because EFI_IMAGE_SIZEOF_SYMBOL is (much) less than
      // UINT32_MAX
      if (untrusted_strings_start + sizeof(string_table_size) > full.size) {
         LOG("Symbol table out of bounds");
         return false;
      }
      memcpy(&string_table_size, full.ptr + untrusted_strings_start, sizeof(string_table_size));
      if (string_table_size < sizeof(string_table_size)) {
         LOG("String table too short: min 4, got %" PRIu32, string_table_size);
         return false;
      }
      // cannot wrap because EFI_IMAGE_SIZEOF_SYMBOL is (much) less than
      // UINT32_MAX
      uint64_t untrusted_strings_end = untrusted_strings_start + (uint64_t)string_table_size;
      if (untrusted_strings_end > full.size) {
         LOG("String table out of bounds: 0x%" PRIx64 " > 0x%zu",
             untrusted_strings_end, full.size);
         return false;
      }
      // little-endian, so if the string table is of length 4 (no strings) last
      // byte will be 0.
      if (full.ptr[untrusted_strings_end - 1] != 0) {
         LOG("String table not NUL-terminated");
         return false;
      }
      /* string & symbol table sanitize end */
      image->symbol_table_offset = untrusted_pointer_to_symbol_table;
      image->string_table_end = untrusted_strings_end;
      image->string_table = (const char *)full.ptr + untrusted_strings_start;
      image->string_table_size = string_table_size;
   }
   return true;
}

bool pe_parse(const uint8_t *const ptr, size_t const len, struct ParsedImage *image,
              bool const verbose, bool const strict, bool const require_relocs)
{
   memset(image, 0, sizeof(*image));
   const struct PeBuffer full = {.ptr = ptr, .size = len};
   if (!parse_headers(full, verbose, image, strict))
      return false;

   if (!validate_data_directories(image->directory, image->directory_entries))
      return false;

   /* Overflow is impossible: max_address is always at least as large as image->image_base */
   uint64_t image_address_space = image->max_address - image->image_base;
   if (image_address_space > UINT32_MAX)
      image_address_space = UINT32_MAX;
   image_address_space &= ~(uint64_t)(image->section_alignment - 1);
   uint64_t const max_address = image->image_base + image_address_space;
   uint32_t last_section_start = image->size_of_headers;
   uint64_t last_virtual_address = 0;
   uint64_t last_virtual_address_end = 0;
   const char *last_section_name = NULL;
   int last_section_name_len = 0;

   bool directories_found[EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES] = { 0 };
   for (uint32_t i = 0; i < image->directory_entries; ++i)
      directories_found[i] = image->directory[i].Size == 0;
   directories_found[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY] = true; // special case

   for (uint32_t i = 0; i < image->n_sections; ++i) {
      int section_name_len;
      // This is not NUL-terminated if section_name_len is 8.
      const char *section_name = get_section_name(image->sections + i, image, &section_name_len);
      if (section_name == NULL)
         return false;
#define LOG_SECTION(msg, ...)                                                                      \
   LOG("Section %" PRIu32 " (name %.*s) " msg, i, section_name_len, section_name, ##__VA_ARGS__)
      if (image->sections[i].PointerToRelocations != 0 ||
          image->sections[i].NumberOfRelocations != 0) {
         LOG_SECTION("contains COFF relocations");
         if (strict)
            return false;
      }

      if (image->sections[i].PointerToLinenumbers != 0 ||
          image->sections[i].NumberOfLinenumbers != 0) {
         LOG_SECTION("contains COFF line numbers");
         if (strict)
            return false;
      }

      /* Validate PointerToRawData and SizeOfRawData */
      if (image->sections[i].PointerToRawData != 0) {
         if (len - last_section_start < image->sections[i].SizeOfRawData) {
            LOG_SECTION("is too long: length is 0x%" PRIx32 " but only 0x%" PRIx32
                        " bytes remaining in file",
                        image->sections[i].SizeOfRawData, (uint32_t)(len - last_section_start));
            return false;
         }
         if (!IS_ALIGNED(image->sections[i].PointerToRawData, image->file_alignment)) {
            LOG_SECTION("has misaligned raw data pointer: pointer is 0x%" PRIx32
                        " but alignment is 0x%" PRIx32,
                        image->sections[i].PointerToRawData, image->file_alignment);
            return false;
         }
         if (!IS_ALIGNED(image->sections[i].SizeOfRawData, image->file_alignment)) {
            LOG_SECTION("has misaligned raw data size: size is 0x%" PRIx32
                        " but alignment is 0x%" PRIx32,
                        image->sections[i].SizeOfRawData, image->file_alignment);
            return false;
         }
         /*
          * If the next section starts after the previous one ends, the data in
          * between can be tampered with without invalidating the signature.
          * This is bad.  All sections must have size and alignment that
          * are multiple of the file alignment, so it is never necessary to
          * have alignment padding between sections.
          */
         if (image->sections[i].PointerToRawData != last_section_start) {
            if (i > 0) {
               LOG_SECTION("starts at 0x%" PRIx32 ", but previous section %.*s ends at 0x%" PRIx32,
                           image->sections[i].PointerToRawData, last_section_name_len,
                           last_section_name, last_section_start);
            } else {
               LOG_SECTION("starts at 0x%" PRIx32 ", but NT headers end at 0x%" PRIx32,
                           image->sections[i].PointerToRawData, last_section_start);
            }
            return false;
         }
         /*
          * It is okay for sections to have data beyond their virtual
          * address size (which is ignored), but not the other way around.
          * VirtualSize specifies the amount of bytes loaded into memory.
          * All of this data must be read from the section.  If
          * SizeOfRawData is less than VirtualSize, there is nowhere to
          * read the last VirtualSize - SizeOfRawData bytes from.
          */
         if (image->sections[i].SizeOfRawData < image->sections[i].Misc.VirtualSize) {
            LOG_SECTION("has size 0x%" PRIx32 " in the file, but "
                        "0x%" PRIx32 " in memory",
                        image->sections[i].SizeOfRawData, image->sections[i].Misc.VirtualSize);
            return false;
         }
         last_section_start += image->sections[i].SizeOfRawData;
         if (verbose) {
            LOG_SECTION("starts at 0x%" PRIx32 " and continues to 0x%" PRIx32,
                        image->sections[i].PointerToRawData,
                        last_section_start);
         }
      } else {
         if (image->sections[i].SizeOfRawData != 0) {
            LOG_SECTION("starts at zero but has nonzero size");
            return false;
         }
         if (verbose)
            LOG_SECTION("has no data on disk");
      }

      /* Validate VirtualAddress and VirtualSize */
      if (image->sections[i].VirtualAddress > image_address_space) {
         LOG_SECTION("has too large VMA: 0x%" PRIx32 " extends beyond address space [0x%" PRIx64
                     ", 0x%" PRIx64 "]",
                     image->sections[i].VirtualAddress, image->image_base, max_address);
         return false;
      }
      // Wraparound is impossible: image->image_base is a uint64_t,
      // image->sections[i].VirtualAddress is bounded by image_address_space,
      // and image_address_space is bounded by image->max_address - image->image_base.
      uint64_t const untrusted_virtual_address = image->sections[i].VirtualAddress + image->image_base;
      if (max_address - untrusted_virtual_address < image->sections[i].Misc.VirtualSize) {
         LOG_SECTION("has virtual address overflow: 0x%" PRIx64 " + 0x%" PRIx32 " > 0x%" PRIx64,
                     untrusted_virtual_address, image->sections[i].Misc.VirtualSize, max_address);
         return false;
      }
      if (verbose)
         LOG_SECTION("has flags 0x%" PRIx32, image->sections[i].Characteristics);
      uint32_t untrusted_characteristics = image->sections[i].Characteristics;
      if ((untrusted_characteristics & pe_section_reserved_bits) != 0) {
         LOG_SECTION("characteristics 0x%08" PRIx32 " has reserved bits",
                     untrusted_characteristics);
         if (strict)
            return false;
      }
      if (untrusted_characteristics & EFI_IMAGE_SCN_CNT_CODE) {
         if (verbose)
            LOG_SECTION("is executable code");
         if (!(untrusted_characteristics & EFI_IMAGE_SCN_MEM_EXECUTE)) {
            LOG_SECTION("is code but has no execute permissions");
            if (strict)
               return false;
         }
         if (untrusted_characteristics & EFI_IMAGE_SCN_MEM_WRITE) {
            LOG_SECTION("is code but has write permissions");
            if (strict)
               return false;
         }
         if (untrusted_characteristics & EFI_IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            LOG_SECTION("is both code and uninitialized data");
            return false;
         }
         if (untrusted_characteristics & EFI_IMAGE_SCN_CNT_INITIALIZED_DATA) {
            LOG_SECTION("is both code and initialized data");
            if (strict)
               return false;
         }
      } else {
         if (untrusted_characteristics & EFI_IMAGE_SCN_CNT_INITIALIZED_DATA) {
            if (verbose)
               LOG_SECTION("is initialized data");
            if (untrusted_characteristics & EFI_IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
               LOG_SECTION("is both initialized and uninitialized data");
               if (strict)
                  return false;
            }
         } else {
            if (verbose) {
               if (untrusted_characteristics & EFI_IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
                  LOG_SECTION("is uninitialized data");
               } else {
                  LOG_SECTION("is not code, initialized data, or uninitialized data");
               }
            }
         }
         if (untrusted_characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) {
            LOG_SECTION("is data but has execute permissions");
            if (strict)
               return false;
         }
      }
      if (untrusted_characteristics & EFI_IMAGE_SCN_ALIGN_64BYTES) {
         uint32_t alignment = 1U << (((untrusted_characteristics & EFI_IMAGE_SCN_ALIGN_64BYTES) >> 20) - 1);
         if (!IS_ALIGNED(untrusted_virtual_address, alignment)) {
            LOG_SECTION("has misaligned VMA for its own alignment: 0x%" PRIx64
                        " not aligned to 0x%" PRIx32,
                        untrusted_virtual_address, alignment);
            return false;
         }
      }
      if (untrusted_characteristics & EFI_IMAGE_SCN_MEM_DISCARDABLE) {
         if (section_name_len != (int)sizeof(".reloc") - 1 ||
             memcmp(section_name, ".reloc", sizeof(".reloc")) != 0) {
            LOG_SECTION("is discardable, which isn't expected");
            if (strict)
               return false;
         } else {
            if (require_relocs) {
               LOG_SECTION("is discardable, causing crashes with some bootloaders");
               return false;
            }
         }
      }
      if ((untrusted_characteristics & (EFI_IMAGE_SCN_MEM_EXECUTE|EFI_IMAGE_SCN_MEM_WRITE)) ==
          (EFI_IMAGE_SCN_MEM_EXECUTE|EFI_IMAGE_SCN_MEM_WRITE)) {
         LOG_SECTION("is both writeable and executable");
         if (strict)
            return false;
      }
      if (untrusted_characteristics &
          (EFI_IMAGE_SCN_CNT_CODE|EFI_IMAGE_SCN_CNT_INITIALIZED_DATA|EFI_IMAGE_SCN_CNT_UNINITIALIZED_DATA)) {
         /* First section in memory must be aligned.  Subsequent ones do not need to be. */
         if (last_virtual_address == 0 && !IS_ALIGNED(untrusted_virtual_address, image->section_alignment)) {
            LOG_SECTION("has misaligned VMA: 0x%" PRIx64 " not aligned to 0x%" PRIx32,
                        untrusted_virtual_address, image->section_alignment);
            return false;
         }
         if (untrusted_virtual_address < last_virtual_address) {
            assert(last_section_name != NULL);
            LOG_SECTION("is not sorted by VA: VA 0x%" PRIx64
                        " < previous section %.*s VA 0x%" PRIx64,
                        untrusted_virtual_address, last_section_name_len, last_section_name,
                        last_virtual_address);
            return false;
         }
         if (untrusted_virtual_address < last_virtual_address_end) {
            assert(last_section_name != NULL);
            LOG_SECTION("overlaps the previous section %.*s: 0x%" PRIx64 " in [0x%" PRIx64
                        ", 0x%" PRIx64 ")",
                        last_section_name_len, last_section_name, untrusted_virtual_address,
                        last_virtual_address, last_virtual_address_end);
            return false;
         }
         last_virtual_address = untrusted_virtual_address;
         last_virtual_address_end = last_virtual_address + image->sections[i].Misc.VirtualSize;
         last_section_name = section_name;
         last_section_name_len = section_name_len;

         for (uint32_t j = 0; j < image->directory_entries; ++j) {
            /* Security directory is special. */
            if (j == EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
               continue;
            }

            if (!directory_in_section(image->directory[j], &image->sections[i], &directories_found[j], j, i)) {
               return false;
            }
         }
      }
   }

   for (uint32_t i = 0; i < image->directory_entries; ++i) {
      if (!directories_found[i]) {
         LOG("Directory %" PRIu32 " present, but not in any section", i);
         return false;
      }
   }

   if (last_section_start == image->size_of_headers) {
      LOG("Image has no sections with data");
      return false;
   }

   if (image->symbol_table_offset != 0) {
      if (verbose)
         LOG("Symbol table starts at offset 0x%" PRIx32, image->symbol_table_offset);
      if (image->symbol_table_offset < last_section_start) {
         LOG("Last section ends at offset 0x%" PRIx32
             ", but symbol table is at offset 0x%" PRIx32
             " which overlaps headers or sections",
             last_section_start, image->symbol_table_offset);
         return false;
      }
   }

   uint32_t untrusted_signature_size = 0;
   uint32_t untrusted_signature_offset = 0;
   if (image->directory_entries > EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
      untrusted_signature_offset = image->directory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
      untrusted_signature_size = image->directory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
   }
   uint32_t string_and_symbol_table_size = image->string_table_end - image->symbol_table_offset;
   if (untrusted_signature_offset == 0) {
      if (verbose) {
         LOG("File is not signed");
         if (string_and_symbol_table_size != len - last_section_start)
            LOG("There are 0x%" PRIx32 " bytes in the string table + symbol table, but 0x%zx bytes after the sections",
                string_and_symbol_table_size, len - last_section_start);
      }
   } else {
      /* sanitize signature offset and size start */
      if (untrusted_signature_offset < last_section_start) {
         LOG("Signature overlaps sections (0x%" PRIx32 " < 0x%" PRIx32 ")",
             untrusted_signature_offset, last_section_start);
         return false;
      }

      if (!IS_ALIGNED(untrusted_signature_offset, 8)) {
         LOG("Signature misaligned (0x%" PRIx32 " not multiple of 8)",
             untrusted_signature_offset);
         return false;
      }

      if (untrusted_signature_offset > len) {
         LOG("Signature starts after end of file (got 0x%" PRIx32 "but only 0x%zu bytes in file)",
             untrusted_signature_size, len);
         return false;
      }

      uint32_t signature_offset = untrusted_signature_offset;

      if (untrusted_signature_size > len - signature_offset) {
         LOG("Signature too large (got 0x%" PRIx32 "but only 0x%zx bytes left in file)",
             untrusted_signature_size, len - signature_offset);
         return false;
      }

      if (untrusted_signature_size + signature_offset != len) {
         LOG("0x%zx bytes of junk after signature", len - (untrusted_signature_size + signature_offset));
         return false;
      }

      uint32_t signature_len = untrusted_signature_size;
      /* sanitize signature offset and size end */
      if (image->string_table_end > signature_offset) {
         LOG("String table ends at 0x%" PRIx32 ", but signature starts at 0x%" PRIx32,
             image->string_table_end, signature_offset);
         return false;
      }
      if (verbose && string_and_symbol_table_size != signature_offset - last_section_start)
         LOG("There are 0x%" PRIx32 " bytes in the string table + symbol table, but 0x%" PRIx32 " bytes between the last section and the signature",
             string_and_symbol_table_size, signature_offset - last_section_start);
      if (!signature_section_check(ptr + signature_offset, signature_len, verbose))
          return false;
   }
   return true;
}
