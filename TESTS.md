### DOS header tests

- [ ] Too short for MZ signature
- [ ] Too short for DOS header
- [ ] No DOS header (starts with `"PE\0\0"`)
- [ ] PE header overlaps DOS header
- [ ] PE header past end of file
- [ ] PE header too close to end of file

### File header tests

- [ ] File is not executable
- [ ] COFF symbol table pointer not zero
- [ ] COFF number of symbols not zero
- [ ] Size of optional header too short
- [ ] Size of optional header too long
- [ ] Size of optional header not multiple of 8
- [ ] Zero sections
- [ ] More than 96 sections
- [ ] NT headers do not fit in image

### Optional header early tests

- [ ] PE32 magic
- [ ] PE32+ magic
- [ ] Endian-swapped file
- [ ] Invalid magic
- [ ] More than 16 data directories

### Image base & alignment tests

- [ ] Image base not multiple of 0x10000
- [ ] Section alignment 0
- [ ] File alignment 0
- [ ] Section alignment not multiple of 0x1000
- [ ] File alignment less than 32
- [ ] File alignment greater than 0x10000
- [ ] File alignment not power of 2
- [ ] File alignment greater than section alignment
- [ ] Section alignment not power of 2
- [ ] Image base not multiple of section alignment

### Size of header tests

- [ ] Headers extend past end of file
- [ ] Headers not multiple of file alignment
- [ ] Headers do not include all section headers

### Optional header size

- [ ] Optional header size and number of data directory entries do not match

### Further tests

- [ ] Invalid optional header
- [ ] Non-zero byte between section headers and end of headers
- [ ] For each section:
    - [ ] COFF relocations
        - [ ] Pointer to and/or number of relocations not zero
        - [ ] Pointer to and/or number of line numbers not zero
    - [ ] Invalid section names
        - [ ] Empty section name
        - [ ] non-NUL NUL byte after NUL byte
        - [ ] $ in section names
        - [ ] Byte not in \[0x21, 0x7E\]
    - [ ] Sections with raw data
        - [ ] Raw data extends past end of file
        - [ ] Raw data pointer misaligned
        - [ ] Raw data pointer of non-first section does not equal end of last section
        - [ ] Raw data pointer of first section does not equal end of NT headers
    - [ ] Sections with no raw data
        - [ ] Section starts at zero but has nonzero size
    - [ ] Virtual address extends after end of address space
    - [ ] Virtual address misaligned
    - [ ] Virtual size + virtual address overflows max address
    - [ ] Characteristics have reserved bits
    - [ ] If a section is code or initialized/uninitialized data:
        - [ ] Sections not sorted by VMA
        - [ ] Sections overlap in memory

### Signatures

- [ ] Signature data directory not present
- [ ] Signature offset zero but size nonzero
- [ ] Padding between last section and signature
- [ ] Signature extends past end of file
- [ ] Signature size not multiple of 8
- [ ] Signature too small (less than sizeof(WIN\_CERTIFICATE))
- [ ] Wrong signature version
- [ ] Wrong signature type
- [ ] Signature length too long (past end of file)
- [ ] Signature length too small (less than sizeof(WIN\_CERTIFICATE))
- [ ] Signature length not 8-byte aligned
- [ ] Signature not valid ASN.1 DER
- [ ] Signature has too many zeros after ASN.1 DER
