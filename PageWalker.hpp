#pragma once

#include "Common.hpp"

// read-only x64 page-table walker.
// every public routine is IRQL <= APC_LEVEL except read_current_cr3 (any IRQL).
// this code never writes a page-table entry, never changes CR3, and never maps new PTEs.

enum page_walk_status_t {
	page_walk_success = 0 ,
	page_walk_not_present ,
	page_walk_invalid_address ,
	page_walk_physical_read_failure ,
	page_walk_unsupported_paging_mode ,
	page_walk_reserved_bit_violation ,
	page_walk_invalid_parameter
};

enum page_mapping_level_t {
	page_mapping_none = 0 ,
	page_mapping_pte_4kb ,
	page_mapping_pde_2mb ,
	page_mapping_pdpte_1gb
};

struct page_table_flags_t {
	BOOLEAN present;
	BOOLEAN writable;        // logical AND of R/W along the walk
	BOOLEAN user;            // logical AND of U/S along the walk
	BOOLEAN execute_disable; // logical OR of NX along the walk
	BOOLEAN accessed;
	BOOLEAN dirty;
	BOOLEAN global;
	BOOLEAN write_through;
	BOOLEAN cache_disable;
	BOOLEAN pat;
	BOOLEAN large_page;
	BOOLEAN reserved_bits_set;
};

struct page_walk_result_t {
	page_walk_status_t status;
	page_mapping_level_t level;

	ULONG64 directory_table_base_used;
	ULONG64 virtual_address;

	ULONG64 pml5e;
	ULONG64 pml4e;
	ULONG64 pdpte;
	ULONG64 pde;
	ULONG64 pte;

	ULONG64 pml5e_physical;
	ULONG64 pml4e_physical;
	ULONG64 pdpte_physical;
	ULONG64 pde_physical;
	ULONG64 pte_physical;

	ULONG64 leaf_entry_physical;
	ULONG64 mapped_page_physical_base;
	ULONG64 resolved_physical_address;
	ULONG64 page_size;
	ULONG64 page_offset;

	BOOLEAN five_level_paging;
	page_table_flags_t flags;
};

inline NTSTATUS page_walk_status_to_ntstatus ( _In_ page_walk_status_t status ) {
	switch ( status ) {
		case page_walk_success: return STATUS_SUCCESS;
		case page_walk_not_present: return STATUS_NOT_FOUND;
		case page_walk_invalid_address: return STATUS_INVALID_ADDRESS;
		case page_walk_physical_read_failure: return STATUS_IN_PAGE_ERROR;
		case page_walk_unsupported_paging_mode: return STATUS_NOT_SUPPORTED;
		case page_walk_reserved_bit_violation: return STATUS_ILLEGAL_INSTRUCTION;
		case page_walk_invalid_parameter:
		default: return STATUS_INVALID_PARAMETER;
	}
}

// cache CPU paging mode (CR4.LA57, EFER.LMA, MAXPHYADDR). PASSIVE_LEVEL. safe to call more than once.
_IRQL_requires_max_ ( PASSIVE_LEVEL )
NTSTATUS page_walk_initialize ( );

_IRQL_requires_max_ ( APC_LEVEL )
BOOLEAN page_walk_is_initialized ( );

_IRQL_requires_max_ ( APC_LEVEL )
BOOLEAN page_walk_uses_five_level ( );

// directory_table_base is a CR3 value (PCID / cache bits are masked internally).
// virtual_address is the address to resolve, result receives the walk output.
_IRQL_requires_max_ ( APC_LEVEL )
NTSTATUS virtual_page_walk ( _In_ ULONG64 directory_table_base ,
							 _In_ ULONG64 virtual_address ,
							 _Out_ page_walk_result_t* result );

_IRQL_requires_max_ ( HIGH_LEVEL )
ULONG64 read_current_cr3 ( );

// reads KPROCESS.DirectoryTableBase from PsInitialSystemProcess (offset 0x28 on x64).
// that field is not documented; failure falls back to the current processor CR3.
_IRQL_requires_max_ ( APC_LEVEL )
NTSTATUS get_system_directory_table_base ( _Out_ PULONG64 directory_table_base );

// reads [virtual_address, virtual_address+size) through the walker and physical copies.
// gaps are left untouched in destination so a zeroed snapshot buffer stays zero there.
_IRQL_requires_max_ ( APC_LEVEL )
NTSTATUS read_virtual_range ( _In_ ULONG64 directory_table_base ,
							  _In_ ULONG64 virtual_address ,
							  _Out_writes_bytes_ ( size ) PVOID destination ,
							  _In_ SIZE_T size ,
							  _Out_opt_ PSIZE_T bytes_read ,
							  _Out_opt_ PSIZE_T bytes_skipped );
