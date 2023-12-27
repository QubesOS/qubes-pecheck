bool signature_section_check(const uint8_t *const ptr, size_t const len);
const EFI_IMAGE_OPTIONAL_HEADER_UNION*
extract_pe_header(const uint8_t *const ptr, size_t const len);

