#define DEBUG_EVENTS        0x1
#define DEBUG_EXCEPTIONS    0x2
#define DEBUG_INFO          0x4
#define DEBUG_ERROR         0x8


#define DEBUG_CONSOLE
#define DEBUG_FILTER     ( DEBUG_EVENTS | DEBUG_EXCEPTIONS | DEBUG_INFO | DEBUG_ERROR )

void dprintf(uint32_t debug_type, const char * format, ...);