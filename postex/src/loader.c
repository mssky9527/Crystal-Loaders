#include <windows.h>
#include "tcg.h"
#include "loader.h"

DECLSPEC_IMPORT LPVOID WINAPI  KERNEL32$VirtualAlloc   ( LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT BOOL   WINAPI  KERNEL32$VirtualProtect ( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT LPVOID WINAPIV MSVCRT$malloc           ( size_t );
DECLSPEC_IMPORT void   WINAPIV MSVCRT$free             ( LPVOID );

__typeof__ ( GetModuleHandleA ) * pGetModuleHandle __attribute__ ( ( section ( ".text" ) ) );
__typeof__ ( GetProcAddress   ) * pGetProcAddress  __attribute__ ( ( section ( ".text" ) ) );

char __DLLDATA__ [ 0 ] __attribute__ ( ( section ( "dll_data" ) ) );
char __KEYDATA__ [ 0 ] __attribute__ ( ( section ( "key_data" ) ) );

FARPROC resolve ( char * mod_name, char * func_name )
{
    HANDLE module = pGetModuleHandle ( mod_name );

    if ( module == NULL ) {
        module = LoadLibraryA ( mod_name );
    }

    return pGetProcAddress ( module, func_name );
}

#ifdef WIN_X86
__declspec ( noinline ) ULONG_PTR caller ( VOID ) { return ( ULONG_PTR ) WIN_GET_CALLER ( ); }
#endif

void go ( LPVOID arguments )
{
    RESOURCE * masked_dll = ( RESOURCE * ) GETRESOURCE ( __DLLDATA__ );
    RESOURCE * xor_key    = ( RESOURCE * ) GETRESOURCE ( __KEYDATA__ );

    char * dll_src = MSVCRT$malloc ( masked_dll->length );

    for ( size_t i = 0; i < masked_dll->length; i++ ) {
        dll_src [ i ] = masked_dll->value [ i ] ^ xor_key->value [ i % xor_key->length ];
    }

    DLLDATA dll_data;
    ParseDLL ( dll_src, &dll_data );

    char * dll_dst = KERNEL32$VirtualAlloc ( NULL, SizeOfDLL ( &dll_data ), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    LoadDLL ( &dll_data, dll_src, dll_dst );

    IMPORTFUNCS  funcs;
    funcs.GetProcAddress = GetProcAddress;
    funcs.LoadLibraryA   = LoadLibraryA;

    ProcessImports ( &funcs, &dll_data, dll_dst );

    RDATA_SECTION rdata;
    memset ( &rdata, 0, sizeof ( RDATA_SECTION ) );

    fix_section_permissions ( &dll_data, dll_dst, &rdata );

    DLLMAIN_FUNC dll_main = EntryPoint ( &dll_data, dll_dst );

    MSVCRT$free ( dll_src );
    
    dll_main ( ( HINSTANCE ) dll_dst, DLL_PROCESS_ATTACH, NULL );
    dll_main ( ( HINSTANCE ) &go, 4, arguments );
}

void fix_section_permissions ( DLLDATA * dll_data, char * dll_dst, RDATA_SECTION * rdata )
{
    DWORD section_count = dll_data->NtHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER * section_hdr = ( IMAGE_SECTION_HEADER * ) PTR_OFFSET ( dll_data->OptionalHeader, dll_data->NtHeaders->FileHeader.SizeOfOptionalHeader );

    for ( size_t i = 0; i < section_count; i++ )
    {
        void * section_dst = dll_dst + section_hdr->VirtualAddress;
        DWORD section_size = section_hdr->SizeOfRawData;
        
        DWORD new_protect;
        DWORD old_protect;

        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) {
            new_protect = PAGE_WRITECOPY;
        }
        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) {
            new_protect = PAGE_READONLY;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) ) {
            new_protect = PAGE_READWRITE;
        }
        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) {
            new_protect = PAGE_EXECUTE;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) ) {
            new_protect = PAGE_EXECUTE_WRITECOPY;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) ) {
            new_protect = PAGE_EXECUTE_READ;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) {
            new_protect = PAGE_EXECUTE_READWRITE;
        }

        KERNEL32$VirtualProtect ( section_dst, section_size, new_protect, &old_protect );

        DWORD hash = ror13hash ( ( const char * ) section_hdr->Name );

        if ( hash == 0xcba738b8 )
        {
            rdata->start  = section_dst;
            rdata->length = section_size;
            rdata->offset = dll_data->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
        }

        section_hdr++;
    }
}
