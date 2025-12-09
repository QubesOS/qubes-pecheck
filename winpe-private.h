#include "PeImage.h"
#include <stdint.h>
#include <stddef.h>

struct PeBuffer {
   const uint8_t *ptr;
   size_t size;
};
bool signature_section_check(const uint8_t *const ptr, size_t const len, bool const verbose);
const EFI_IMAGE_OPTIONAL_HEADER_UNION* extract_pe_header(const struct PeBuffer b);

