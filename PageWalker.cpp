#include "PageWalker.hpp"
#include "PhysicalMemory.hpp"

static const ULONG64 k_pte_present = 1ULL << 0;
static const ULONG64 k_pte_writable = 1ULL << 1;
static const ULONG64 k_pte_user = 1ULL << 2;
static const ULONG64 k_pte_pwt = 1ULL << 3;
static const ULONG64 k_pte_pcd = 1ULL << 4;
static const ULONG64 k_pte_accessed = 1ULL << 5;
static const ULONG64 k_pte_dirty = 1ULL << 6;
static const ULONG64 k_pte_page_size = 1ULL << 7;
static const ULONG64 k_pte_global = 1ULL << 8;
static const ULONG64 k_pte_pat_large = 1ULL << 12;
static const ULONG64 k_pte_nx = 1ULL << 63;

static const ULONG64 k_default_phys_mask = 0x000FFFFFFFFFFFFFULL;
static const ULONG64 k_default_frame_mask = 0x000FFFFFFFFFF000ULL;
static const SIZE_T k_kprocess_directory_table_base_offset_x64 = 0x28;

struct paging_state_t {
	BOOLEAN initialized;
	BOOLEAN long_mode_active;
	BOOLEAN five_level;
	UCHAR max_phy_addr;
	ULONG64 phys_addr_mask;
	ULONG64 frame_mask;
};

static paging_state_t g_paging = { };

static VOID reset_page_walk_result ( _Out_ page_walk_result_t* result , _In_ ULONG64 dtb , _In_ ULONG64 va ) {
	RtlZeroMemory ( result , sizeof ( *result ) );
	result->directory_table_base_used = dtb;
	result->virtual_address = va;
	result->status = page_walk_invalid_parameter;
	result->level = page_mapping_none;
}

static BOOLEAN is_canonical ( _In_ ULONG64 va , _In_ BOOLEAN five_level ) {
	LONG64 signed_va = static_cast< LONG64 >( va );
	if ( five_level ) {
		LONG64 top = signed_va >> 56;
		return top == 0 || top == -1;
	}
	LONG64 top = signed_va >> 47;
	return top == 0 || top == -1;
}

static ULONG64 read_msr_efer ( ) {
	return __readmsr ( 0xC0000080 );
}

static BOOLEAN cpu_supports_leaf ( _In_ INT32 leaf ) {
	INT32 info [ 4 ] = { };
	__cpuid ( info , 0x80000000 );
	return static_cast< UINT32 >( info [ 0 ] ) >= static_cast< UINT32 >( leaf );
}

static UCHAR query_max_phy_addr ( ) {
	if ( !cpu_supports_leaf ( 0x80000008 ) ) return 52;

	INT32 info [ 4 ] = { };
	__cpuid ( info , 0x80000008 );
	UCHAR max_phy = static_cast< UCHAR >( info [ 0 ] & 0xFF );
	if ( max_phy < 36 || max_phy > 52 ) return 52;
	return max_phy;
}

static ULONG64 make_phys_mask ( _In_ UCHAR max_phy_addr ) {
	if ( max_phy_addr >= 64 ) return ~static_cast< ULONG64 >( 0 );
	return ( 1ULL << max_phy_addr ) - 1ULL;
}

static ULONG64 frame_from_entry ( _In_ ULONG64 entry ) {
	return entry & g_paging.frame_mask;
}

static NTSTATUS read_table_entry ( _In_ ULONG64 table_physical_base ,
								   _In_ ULONG index ,
								   _Out_ PULONG64 entry ,
								   _Out_ PULONG64 entry_physical ) {
	*entry = 0;
	*entry_physical = 0;
	if ( index > 511 ) return STATUS_INVALID_PARAMETER;

	ULONG64 entry_pa = 0;
	if ( !add_u64 ( table_physical_base , static_cast< ULONG64 >( index ) * 8ULL , &entry_pa ) )
		return STATUS_INTEGER_OVERFLOW;

	SIZE_T copied = 0;
	NTSTATUS status = memory::copy_physical_memory ( entry_pa , entry , sizeof ( *entry ) , &copied );
	if ( !NT_SUCCESS ( status ) || copied != sizeof ( *entry ) )
		return NT_SUCCESS ( status ) ? STATUS_PARTIAL_COPY : status;

	*entry_physical = entry_pa;
	return STATUS_SUCCESS;
}

static VOID accumulate_non_leaf ( _Inout_ page_table_flags_t* flags , _In_ ULONG64 entry ) {
	flags->present = BooleanFlagOn ( entry , k_pte_present );
	flags->writable = flags->writable && BooleanFlagOn ( entry , k_pte_writable );
	flags->user = flags->user && BooleanFlagOn ( entry , k_pte_user );
	flags->execute_disable = flags->execute_disable || BooleanFlagOn ( entry , k_pte_nx );
	flags->accessed = flags->accessed || BooleanFlagOn ( entry , k_pte_accessed );
}

static VOID apply_leaf_flags ( _Inout_ page_table_flags_t* flags , _In_ ULONG64 entry , _In_ BOOLEAN large_page ) {
	accumulate_non_leaf ( flags , entry );
	flags->dirty = BooleanFlagOn ( entry , k_pte_dirty );
	flags->global = BooleanFlagOn ( entry , k_pte_global );
	flags->write_through = BooleanFlagOn ( entry , k_pte_pwt );
	flags->cache_disable = BooleanFlagOn ( entry , k_pte_pcd );
	flags->large_page = large_page;
	flags->pat = large_page ? BooleanFlagOn ( entry , k_pte_pat_large )
							: BooleanFlagOn ( entry , k_pte_page_size );
}

static BOOLEAN reserved_set_1gb ( _In_ ULONG64 entry ) {
	ULONG64 reserved = entry & static_cast< ULONG64 >( 0x000000003FFFE000ULL );
	return reserved != 0;
}

static BOOLEAN reserved_set_2mb ( _In_ ULONG64 entry ) {
	ULONG64 reserved = entry & static_cast< ULONG64 >( 0x00000000001FE000ULL );
	return reserved != 0;
}

static NTSTATUS finish_leaf ( _Inout_ page_walk_result_t* result ,
							  _In_ ULONG64 entry ,
							  _In_ ULONG64 entry_physical ,
							  _In_ ULONG64 page_size ,
							  _In_ page_mapping_level_t level ,
							  _In_ BOOLEAN reserved_bits ) {
	ULONG64 page_mask = ~( page_size - 1ULL );
	ULONG64 frame = entry & g_paging.frame_mask & page_mask;
	ULONG64 offset = result->virtual_address & ( page_size - 1ULL );

	result->leaf_entry_physical = entry_physical;
	result->mapped_page_physical_base = frame;
	result->resolved_physical_address = frame + offset;
	result->page_size = page_size;
	result->page_offset = offset;
	result->level = level;
	result->flags.reserved_bits_set = reserved_bits;

	if ( reserved_bits ) {
		result->status = page_walk_reserved_bit_violation;
		return page_walk_status_to_ntstatus ( result->status );
	}

	result->status = page_walk_success;
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS page_walk_initialize ( ) {
	paging_state_t state = { };

	ULONG64 cr0 = __readcr0 ( );
	ULONG64 cr4 = __readcr4 ( );
	ULONG64 efer = read_msr_efer ( );

	BOOLEAN paging = BooleanFlagOn ( cr0 , 1ULL << 31 );
	BOOLEAN pae = BooleanFlagOn ( cr4 , 1ULL << 5 );
	BOOLEAN lma = BooleanFlagOn ( efer , 1ULL << 10 );

	if ( !paging || !pae || !lma ) {
		g_paging = { };
		g_paging.initialized = TRUE;
		g_paging.long_mode_active = FALSE;
		return STATUS_NOT_SUPPORTED;
	}

	state.initialized = TRUE;
	state.long_mode_active = TRUE;
	state.five_level = BooleanFlagOn ( cr4 , 1ULL << 12 );
	state.max_phy_addr = query_max_phy_addr ( );
	state.phys_addr_mask = make_phys_mask ( state.max_phy_addr );
	state.frame_mask = state.phys_addr_mask & ~static_cast< ULONG64 >( PAGE_SIZE - 1 );

	if ( !state.frame_mask ) {
		state.phys_addr_mask = k_default_phys_mask;
		state.frame_mask = k_default_frame_mask;
		state.max_phy_addr = 52;
	}

	g_paging = state;
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN page_walk_is_initialized ( ) {
	return g_paging.initialized != FALSE;
}

_Use_decl_annotations_
BOOLEAN page_walk_uses_five_level ( ) {
	return g_paging.initialized != FALSE && g_paging.five_level != FALSE;
}

_Use_decl_annotations_
ULONG64 read_current_cr3 ( ) {
	return __readcr3 ( );
}

_Use_decl_annotations_
NTSTATUS get_system_directory_table_base ( PULONG64 directory_table_base ) {
	if ( !directory_table_base ) return STATUS_INVALID_PARAMETER;
	*directory_table_base = 0;

	// isolated undocumented adapter: KPROCESS.DirectoryTableBase has been at +0x28 on x64
	// for a long span of windows versions. if the value has no frame address, fall back to
	// the current processor CR3 (correct when this thread is in the system process).
	PEPROCESS system_process = PsInitialSystemProcess;
	ULONG64 dtb = 0;

	if ( system_process ) {
		RtlCopyMemory ( &dtb ,
						reinterpret_cast< PUCHAR >( system_process ) + k_kprocess_directory_table_base_offset_x64 ,
						sizeof ( dtb ) );
	}

	ULONG64 frame = dtb & ( g_paging.initialized ? g_paging.frame_mask : k_default_frame_mask );
	if ( !frame ) dtb = read_current_cr3 ( );

	*directory_table_base = dtb;
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS virtual_page_walk ( ULONG64 directory_table_base ,
							 ULONG64 virtual_address ,
							 page_walk_result_t* result ) {
	if ( !result ) return STATUS_INVALID_PARAMETER;

	reset_page_walk_result ( result , directory_table_base , virtual_address );
	result->five_level_paging = g_paging.five_level;

	if ( !g_paging.initialized || !g_paging.long_mode_active ) {
		result->status = page_walk_unsupported_paging_mode;
		return page_walk_status_to_ntstatus ( result->status );
	}

	if ( !is_canonical ( virtual_address , g_paging.five_level ) ) {
		result->status = page_walk_invalid_address;
		return page_walk_status_to_ntstatus ( result->status );
	}

	ULONG64 pml_base = directory_table_base & g_paging.frame_mask;
	if ( !pml_base ) {
		result->status = page_walk_invalid_parameter;
		return STATUS_INVALID_PARAMETER;
	}

	page_table_flags_t flags = { };
	flags.present = TRUE;
	flags.writable = TRUE;
	flags.user = TRUE;

	ULONG64 table_pa = pml_base;
	NTSTATUS status;

	if ( g_paging.five_level ) {
		ULONG index = static_cast< ULONG >( ( virtual_address >> 48 ) & 0x1FF );
		status = read_table_entry ( table_pa , index , &result->pml5e , &result->pml5e_physical );
		if ( !NT_SUCCESS ( status ) ) {
			result->status = page_walk_physical_read_failure;
			return page_walk_status_to_ntstatus ( result->status );
		}
		accumulate_non_leaf ( &flags , result->pml5e );
		if ( !BooleanFlagOn ( result->pml5e , k_pte_present ) ) {
			result->flags = flags;
			result->flags.present = FALSE;
			result->status = page_walk_not_present;
			return page_walk_status_to_ntstatus ( result->status );
		}
		if ( BooleanFlagOn ( result->pml5e , k_pte_page_size ) ) {
			result->flags = flags;
			result->flags.reserved_bits_set = TRUE;
			result->status = page_walk_reserved_bit_violation;
			return page_walk_status_to_ntstatus ( result->status );
		}
		table_pa = frame_from_entry ( result->pml5e );
		if ( !table_pa ) {
			result->status = page_walk_not_present;
			return page_walk_status_to_ntstatus ( result->status );
		}
	}

	{
		ULONG index = static_cast< ULONG >( ( virtual_address >> 39 ) & 0x1FF );
		status = read_table_entry ( table_pa , index , &result->pml4e , &result->pml4e_physical );
		if ( !NT_SUCCESS ( status ) ) {
			result->status = page_walk_physical_read_failure;
			return page_walk_status_to_ntstatus ( result->status );
		}
		accumulate_non_leaf ( &flags , result->pml4e );
		if ( !BooleanFlagOn ( result->pml4e , k_pte_present ) ) {
			result->flags = flags;
			result->flags.present = FALSE;
			result->status = page_walk_not_present;
			return page_walk_status_to_ntstatus ( result->status );
		}
		if ( BooleanFlagOn ( result->pml4e , k_pte_page_size ) ) {
			result->flags = flags;
			result->flags.reserved_bits_set = TRUE;
			result->status = page_walk_reserved_bit_violation;
			return page_walk_status_to_ntstatus ( result->status );
		}
		table_pa = frame_from_entry ( result->pml4e );
		if ( !table_pa ) {
			result->status = page_walk_not_present;
			return page_walk_status_to_ntstatus ( result->status );
		}
	}

	{
		ULONG index = static_cast< ULONG >( ( virtual_address >> 30 ) & 0x1FF );
		status = read_table_entry ( table_pa , index , &result->pdpte , &result->pdpte_physical );
		if ( !NT_SUCCESS ( status ) ) {
			result->status = page_walk_physical_read_failure;
			return page_walk_status_to_ntstatus ( result->status );
		}
		accumulate_non_leaf ( &flags , result->pdpte );
		if ( !BooleanFlagOn ( result->pdpte , k_pte_present ) ) {
			result->flags = flags;
			result->flags.present = FALSE;
			result->status = page_walk_not_present;
			return page_walk_status_to_ntstatus ( result->status );
		}

		if ( BooleanFlagOn ( result->pdpte , k_pte_page_size ) ) {
			apply_leaf_flags ( &flags , result->pdpte , TRUE );
			result->flags = flags;
			result->pte_physical = 0;
			result->pde_physical = 0;
			return finish_leaf ( result ,
								 result->pdpte ,
								 result->pdpte_physical ,
								 0x40000000ULL ,
								 page_mapping_pdpte_1gb ,
								 reserved_set_1gb ( result->pdpte ) );
		}

		table_pa = frame_from_entry ( result->pdpte );
		if ( !table_pa ) {
			result->status = page_walk_not_present;
			return page_walk_status_to_ntstatus ( result->status );
		}
	}

	{
		ULONG index = static_cast< ULONG >( ( virtual_address >> 21 ) & 0x1FF );
		status = read_table_entry ( table_pa , index , &result->pde , &result->pde_physical );
		if ( !NT_SUCCESS ( status ) ) {
			result->status = page_walk_physical_read_failure;
			return page_walk_status_to_ntstatus ( result->status );
		}
		accumulate_non_leaf ( &flags , result->pde );
		if ( !BooleanFlagOn ( result->pde , k_pte_present ) ) {
			result->flags = flags;
			result->flags.present = FALSE;
			result->status = page_walk_not_present;
			return page_walk_status_to_ntstatus ( result->status );
		}

		if ( BooleanFlagOn ( result->pde , k_pte_page_size ) ) {
			apply_leaf_flags ( &flags , result->pde , TRUE );
			result->flags = flags;
			result->pte_physical = 0;
			return finish_leaf ( result ,
								 result->pde ,
								 result->pde_physical ,
								 0x200000ULL ,
								 page_mapping_pde_2mb ,
								 reserved_set_2mb ( result->pde ) );
		}

		table_pa = frame_from_entry ( result->pde );
		if ( !table_pa ) {
			result->status = page_walk_not_present;
			return page_walk_status_to_ntstatus ( result->status );
		}
	}

	{
		ULONG index = static_cast< ULONG >( ( virtual_address >> 12 ) & 0x1FF );
		status = read_table_entry ( table_pa , index , &result->pte , &result->pte_physical );
		if ( !NT_SUCCESS ( status ) ) {
			result->status = page_walk_physical_read_failure;
			return page_walk_status_to_ntstatus ( result->status );
		}
		accumulate_non_leaf ( &flags , result->pte );
		if ( !BooleanFlagOn ( result->pte , k_pte_present ) ) {
			result->flags = flags;
			result->flags.present = FALSE;
			result->status = page_walk_not_present;
			return page_walk_status_to_ntstatus ( result->status );
		}

		apply_leaf_flags ( &flags , result->pte , FALSE );
		result->flags = flags;
		return finish_leaf ( result ,
							 result->pte ,
							 result->pte_physical ,
							 PAGE_SIZE ,
							 page_mapping_pte_4kb ,
							 FALSE );
	}
}

_Use_decl_annotations_
NTSTATUS read_virtual_range ( ULONG64 directory_table_base ,
							  ULONG64 virtual_address ,
							  PVOID destination ,
							  SIZE_T size ,
							  PSIZE_T bytes_read ,
							  PSIZE_T bytes_skipped ) {
	if ( bytes_read ) *bytes_read = 0;
	if ( bytes_skipped ) *bytes_skipped = 0;
	if ( !destination || !size ) return STATUS_INVALID_PARAMETER;

	ULONG64 range_end = 0;
	if ( !add_u64 ( virtual_address , static_cast< ULONG64 >( size ) , &range_end ) )
		return STATUS_INTEGER_OVERFLOW;

	SIZE_T read_total = 0;
	SIZE_T skip_total = 0;
	PUCHAR dest = static_cast< PUCHAR >( destination );
	ULONG64 va = virtual_address;
	SIZE_T remaining = size;

	while ( remaining > 0 ) {
		page_walk_result_t walk = { };
		NTSTATUS walk_status = virtual_page_walk ( directory_table_base , va , &walk );

		SIZE_T chunk = bytes_to_end_of_page ( va );
		if ( chunk > remaining ) chunk = remaining;

		if ( NT_SUCCESS ( walk_status ) && walk.status == page_walk_success ) {
			SIZE_T copied = 0;
			NTSTATUS copy_status = memory::copy_physical_memory ( walk.resolved_physical_address ,
																  dest ,
																  chunk ,
																  &copied );
			if ( !NT_SUCCESS ( copy_status ) || copied != chunk ) skip_total += chunk;
			else read_total += copied;
		}
		else {
			skip_total += chunk;
		}

		dest += chunk;
		va += chunk;
		remaining -= chunk;
	}

	if ( bytes_read ) *bytes_read = read_total;
	if ( bytes_skipped ) *bytes_skipped = skip_total;

	if ( !read_total ) return STATUS_UNSUCCESSFUL;
	if ( skip_total ) return STATUS_PARTIAL_COPY;
	return STATUS_SUCCESS;
}
