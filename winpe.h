#include <stdint.h>

struct IMAGE_DOS_HEADER
{
   uint16_t e_magic;
   uint16_t e_cblp;
   uint16_t e_cb;
   uint16_t e_crlc;
   uint16_t e_cparhdr;
   uint16_t e_minalloc;
   uint16_t e_maxalloc;
   uint16_t e_ss, e_sp;
   uint16_t e_csum;
   uint16_t e_ip;
   uint16_t e_cs;
   uint16_t e_lfarlc;
   uint16_t e_ovno;
   uint16_t e_res1[4];
   uint16_t e_oemid;
   uint16_t e_oeminfo;
   uint16_t e_res2[10];
   uint32_t e_lfanew;
} __attribute__((__may_alias__));

typedef struct IMAGE_FILE_HEADER {
  uint16_t                Machine;
  uint16_t                NumberOfSections;
  uint32_t                TimeDateStamp;
  uint32_t                PointerToSymbolTable;
  uint32_t                NumberOfSymbols;
  uint16_t                SizeOfOptionalHeader;
  uint16_t                Characteristics;
} __attribute__((__may_alias__)) IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct IMAGE_DATA_DIRECTORY {
  uint32_t VirtualAddress;
  uint32_t size;
} __attribute__((__may_alias__)) IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct IMAGE_SECTION_HEADER {
   uint8_t  Name[8];
   uint32_t VirtualSize;
   uint32_t VirtualAddress;
   uint32_t SizeOfRawData;
   uint32_t PointerToRawData;
   uint32_t PointerToRelocations;
   uint32_t PointerToLineNumbers;
   uint16_t NumberOfRelocations;
   uint16_t NumberOfLineNumbers;
   uint32_t Characteristics;
} __attribute__((__may_alias__)) IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
typedef struct IMAGE_OPTIONAL_HEADER32 {
  uint16_t                Magic;
  uint8_t                 MajorLinkerVersion;
  uint8_t                 MinorLinkerVersion;
  uint32_t                SizeOfCode;
  uint32_t                SizeOfInitializedData;
  uint32_t                SizeOfUninitializedData;
  uint32_t                AddressOfEntryPoint;
  uint32_t                BaseOfCode;
  uint32_t                BaseOfData;
  uint32_t                ImageBase;
  uint32_t                SectionAlignment;
  uint32_t                FileAlignment;
  uint16_t                MajorOperatingSystemVersion;
  uint16_t                MinorOperatingSystemVersion;
  uint16_t                MajorImageVersion;
  uint16_t                MinorImageVersion;
  uint16_t                MajorSubsystemVersion;
  uint16_t                MinorSubsystemVersion;
  uint32_t                Win32VersionValue;
  uint32_t                SizeOfImage;
  uint32_t                SizeOfHeaders;
  uint32_t                CheckSum;
  uint16_t                Subsystem;
  uint16_t                DllCharacteristics;
  uint32_t                SizeOfStackReserve;
  uint32_t                SizeOfStackCommit;
  uint32_t                SizeOfHeapReserve;
  uint32_t                SizeOfHeapCommit;
  uint32_t                LoaderFlags;
  uint32_t                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY    DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} __attribute__((__may_alias__)) IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_OPTIONAL_HEADER64 {
  uint16_t                Magic;
  uint8_t                 MajorLinkerVersion;
  uint8_t                 MinorLinkerVersion;
  uint32_t                SizeOfCode;
  uint32_t                SizeOfInitializedData;
  uint32_t                SizeOfUninitializedData;
  uint32_t                AddressOfEntryPoint;
  uint32_t                BaseOfCode;
  uint64_t                ImageBase;
  uint32_t                SectionAlignment;
  uint32_t                FileAlignment;
  uint16_t                MajorOperatingSystemVersion;
  uint16_t                MinorOperatingSystemVersion;
  uint16_t                MajorImageVersion;
  uint16_t                MinorImageVersion;
  uint16_t                MajorSubsystemVersion;
  uint16_t                MinorSubsystemVersion;
  uint32_t                Win32VersionValue;
  uint32_t                SizeOfImage;
  uint32_t                SizeOfHeaders;
  uint32_t                CheckSum;
  uint16_t                Subsystem;
  uint16_t                DllCharacteristics;
  uint64_t                SizeOfStackReserve;
  uint64_t                SizeOfStackCommit;
  uint64_t                SizeOfHeapReserve;
  uint64_t                SizeOfHeapCommit;
  uint32_t                LoaderFlags;
  uint32_t                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY    DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} __attribute__((__may_alias__)) IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_NT_HEADERS32 {
   uint32_t Signature;
   IMAGE_FILE_HEADER FileHeader;
   IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} __attribute__((__may_alias__)) IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct IMAGE_NT_HEADERS64 {
   uint32_t Signature;
   IMAGE_FILE_HEADER FileHeader;
   IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} __attribute__((__may_alias__)) IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

struct SharedNtHeader {
   uint32_t          Signature;
   IMAGE_FILE_HEADER FileHeader;
   uint16_t          Magic;
   uint8_t           MajorLinkerVersion;
   uint8_t           MinorLinkerVersion;
   uint32_t          SizeOfCode;
} __attribute__((__may_alias__));
static_assert(sizeof(struct SharedNtHeader) == 32, "bad size of struct SharedNtHeader");

union PeHeader {
   struct SharedNtHeader shared;
   IMAGE_NT_HEADERS32    pe32;
   IMAGE_NT_HEADERS64    pe32p;
} __attribute__((__may_alias__));

struct ParsedImage {
   uint64_t image_base;
   uint32_t file_alignment;
   uint32_t section_alignment;
   IMAGE_DATA_DIRECTORY const *directory;
   IMAGE_SECTION_HEADER const *sections;
   uint32_t directory_entries;
   uint32_t n_sections;
   uint32_t size_of_headers;
   uint32_t _pad0;
};
