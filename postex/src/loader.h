#define GETRESOURCE(x) ( char * ) &x

#define memset(x, y, z) __stosb ( ( unsigned char * ) x, y, z );

typedef struct {
    int  length;
    char value [ ];
} RESOURCE;

typedef struct {
   char* start; // The start address of the .rdata section
   DWORD length; // The length (Size of Raw Data) of the .rdata section
   DWORD offset; // The obfuscation start offset
} RDATA_SECTION, *PRDATA_SECTION;

void go ( );
void fix_section_permissions ( DLLDATA * dll_data, char * dll_dst, RDATA_SECTION * rdata );
