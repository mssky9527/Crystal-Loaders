#define GETRESOURCE(x) ( char * ) &x

#define memset(x, y, z) __stosb ( ( unsigned char * ) x, y, z );

typedef struct {
    int  length;
    char value [ ];
} RESOURCE;

void go ( );
void fix_section_permissions ( DLLDATA * dll_data, char * dll_dst, ALLOCATED_MEMORY_REGION * region );
ALLOCATED_MEMORY_LABEL get_label_from_section_header ( IMAGE_SECTION_HEADER * section_hdr );
