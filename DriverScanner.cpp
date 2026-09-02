#include "DriverScanner.hpp"
#include "PhysicalMemory.hpp"

#include <aux_klib.h>

#pragma comment(lib, "aux_klib.lib")

static VOID copy_ansi_to_wide ( _In_opt_z_ const UCHAR* source ,
								_Out_writes_z_ ( wide_count ) PWCHAR destination ,
								_In_ SIZE_T wide_count ) {
	if ( !destination || !wide_count ) return;

	RtlZeroMemory ( destination , wide_count * sizeof ( WCHAR ) );
	if ( !source ) return;

	SIZE_T i = 0;
	for ( ; i + 1 < wide_count && source [ i ] != '\0'; ++i )
		destination [ i ] = static_cast< WCHAR >( source [ i ] );
	destination [ i ] = L'\0';
}

static VOID extract_file_name ( _In_ PCWSTR full_path ,
								_Out_writes_z_ ( name_count ) PWCHAR file_name ,
								_In_ SIZE_T name_count ) {
	RtlZeroMemory ( file_name , name_count * sizeof ( WCHAR ) );
	if ( !full_path || !name_count ) return;

	PCWSTR last = full_path;
	for ( PCWSTR p = full_path; *p != L'\0'; ++p ) {
		if ( *p == L'\\' || *p == L'/' ) last = p + 1;
	}

	SIZE_T i = 0;
	for ( ; i + 1 < name_count && last [ i ] != L'\0'; ++i )
		file_name [ i ] = last [ i ];
	file_name [ i ] = L'\0';
}

static VOID record_anomaly ( _Inout_ driver_scan_result_t* result ,
							 _In_ ULONG rva ,
							 _In_ ULONG size ,
							 _In_ page_anomaly_kind_t kind ,
							 _In_ page_walk_status_t walk_status ) {
	if ( !result->anomalies || result->anomaly_count >= result->anomaly_capacity ) return;

	page_anomaly_t* entry = &result->anomalies [ result->anomaly_count++ ];
	entry->rva = rva;
	entry->size = size;
	entry->kind = kind;
	entry->walk_status = walk_status;
}

static NTSTATUS enumerate_loaded_modules ( _Outptr_result_bytebuffer_ ( *byte_count ) AUX_MODULE_EXTENDED_INFO** modules ,
										   _Out_ PULONG count ,
										   _Out_ PULONG byte_count ) {
	*modules = nullptr;
	*count = 0;
	*byte_count = 0;

	ULONG required = 0;
	NTSTATUS status = AuxKlibQueryModuleInformation ( &required ,
													  sizeof ( AUX_MODULE_EXTENDED_INFO ) ,
													  nullptr );

	if ( status != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS ( status ) ) return status;
	if ( !required || ( required % sizeof ( AUX_MODULE_EXTENDED_INFO ) ) != 0 ) return STATUS_UNSUCCESSFUL;

	static const ULONG k_max_retries = 4;
	for ( ULONG attempt = 0; attempt < k_max_retries; ++attempt ) {
		PVOID buffer = allocate_nonpaged ( required , PW_POOL_TAG_SCAN );
		if ( !buffer ) return STATUS_INSUFFICIENT_RESOURCES;

		ULONG buffer_size = required;
		status = AuxKlibQueryModuleInformation ( &buffer_size ,
												 sizeof ( AUX_MODULE_EXTENDED_INFO ) ,
												 buffer );

		if ( NT_SUCCESS ( status ) ) {
			if ( ( buffer_size % sizeof ( AUX_MODULE_EXTENDED_INFO ) ) != 0 ) {
				free_pool ( buffer , PW_POOL_TAG_SCAN );
				return STATUS_UNSUCCESSFUL;
			}
			*modules = static_cast< AUX_MODULE_EXTENDED_INFO* >( buffer );
			*byte_count = buffer_size;
			*count = buffer_size / sizeof ( AUX_MODULE_EXTENDED_INFO );
			return STATUS_SUCCESS;
		}

		free_pool ( buffer , PW_POOL_TAG_SCAN );
		if ( status != STATUS_BUFFER_TOO_SMALL ) return status;

		required = buffer_size;
		if ( !required ) return STATUS_UNSUCCESSFUL;
	}

	return STATUS_BUFFER_TOO_SMALL;
}

_Use_decl_annotations_
NTSTATUS initialize_driver_scan ( ) {
	NTSTATUS status = AuxKlibInitialize ( );
	if ( !NT_SUCCESS ( status ) ) return status;
	return page_walk_initialize ( );
}

_Use_decl_annotations_
VOID destroy_scan_result ( driver_scan_result_t** result ) {
	if ( !result || !*result ) return;

	driver_scan_result_t* object = *result;
	free_pool ( object->image_snapshot , PW_POOL_TAG_SCAN );
	free_pool ( object->anomalies , PW_POOL_TAG_SCAN );
	free_pool ( object , PW_POOL_TAG_SCAN );
	*result = nullptr;
}

_Use_decl_annotations_
VOID destroy_scan_set ( driver_scan_set_t** set ) {
	if ( !set || !*set ) return;

	driver_scan_set_t* object = *set;
	if ( object->modules ) {
		for ( ULONG i = 0; i < object->count; ++i )
			destroy_scan_result ( &object->modules [ i ] );
		free_pool ( object->modules , PW_POOL_TAG_SCAN );
	}
	free_pool ( object , PW_POOL_TAG_SCAN );
	*set = nullptr;
}

_Use_decl_annotations_
NTSTATUS scan_driver_module ( ULONG64 directory_table_base ,
							  ULONG64 image_base ,
							  SIZE_T image_size ,
							  PCWSTR full_path ,
							  const driver_scan_options_t* options ,
							  PSIZE_T remaining_snapshot_budget ,
							  driver_scan_result_t** result ) {
	if ( !result || !options ) return STATUS_INVALID_PARAMETER;
	*result = nullptr;
	if ( !image_base || !image_size ) return STATUS_INVALID_PARAMETER;

	ULONG64 range_end = 0;
	if ( !add_u64 ( image_base , static_cast< ULONG64 >( image_size ) , &range_end ) )
		return STATUS_INTEGER_OVERFLOW;

	driver_scan_result_t* object = static_cast< driver_scan_result_t* >(
		allocate_nonpaged ( sizeof ( driver_scan_result_t ) , PW_POOL_TAG_SCAN ) );
	if ( !object ) return STATUS_INSUFFICIENT_RESOURCES;

	object->dll_base = image_base;
	object->image_size = image_size;
	object->scan_status = driver_scan_ok;

	if ( full_path ) {
		SIZE_T i = 0;
		for ( ; i + 1 < RTL_NUMBER_OF ( object->full_path ) && full_path [ i ] != L'\0'; ++i )
			object->full_path [ i ] = full_path [ i ];
		object->full_path [ i ] = L'\0';
		extract_file_name ( object->full_path , object->file_name , RTL_NUMBER_OF ( object->file_name ) );
	}

	if ( options->record_anomalies && options->max_anomalies_per_module ) {
		SIZE_T anomaly_bytes = 0;
		if ( mul_size ( options->max_anomalies_per_module , sizeof ( page_anomaly_t ) , &anomaly_bytes ) ) {
			object->anomalies = static_cast< page_anomaly_t* >(
				allocate_nonpaged ( anomaly_bytes , PW_POOL_TAG_SCAN ) );
			if ( object->anomalies ) object->anomaly_capacity = options->max_anomalies_per_module;
		}
	}

	object->pe_status = read_pe_header ( directory_table_base , image_base , image_size , &object->pe );

	if ( !NT_SUCCESS ( object->pe_status ) ) {
		object->scan_status = driver_scan_pe_parse_failed;
	}
	else if ( object->pe.size_of_image && static_cast< SIZE_T >( object->pe.size_of_image ) < image_size ) {
		image_size = object->pe.size_of_image;
		object->image_size = image_size;
		if ( !add_u64 ( image_base , static_cast< ULONG64 >( image_size ) , &range_end ) ) {
			destroy_scan_result ( &object );
			return STATUS_INTEGER_OVERFLOW;
		}
	}

	SIZE_T snapshot_cap = image_size;
	if ( options->max_snapshot_per_module && snapshot_cap > options->max_snapshot_per_module )
		snapshot_cap = options->max_snapshot_per_module;
	if ( remaining_snapshot_budget && snapshot_cap > *remaining_snapshot_budget )
		snapshot_cap = *remaining_snapshot_budget;

	if ( options->capture_image_snapshot && snapshot_cap ) {
		object->image_snapshot = allocate_nonpaged ( snapshot_cap , PW_POOL_TAG_SCAN );
		if ( !object->image_snapshot ) {
			object->scan_status = driver_scan_allocation_failed;
		}
		else {
			object->snapshot_size = snapshot_cap;
			if ( remaining_snapshot_budget ) *remaining_snapshot_budget -= snapshot_cap;
			if ( snapshot_cap < image_size && object->scan_status == driver_scan_ok )
				object->scan_status = driver_scan_snapshot_budget_exhausted;
		}
	}

	ULONG64 va = image_base;
	BOOLEAN saw_resident_page = FALSE;

	while ( va < range_end ) {
		page_walk_result_t walk = { };
		NTSTATUS walk_nt = virtual_page_walk ( directory_table_base , va , &walk );

		SIZE_T chunk = bytes_to_end_of_page ( va );
		ULONG64 remaining_in_image = range_end - va;
		if ( static_cast< ULONG64 >( chunk ) > remaining_in_image )
			chunk = static_cast< SIZE_T >( remaining_in_image );

		ULONG rva = static_cast< ULONG >( va - image_base );
		BOOLEAN in_snapshot = object->image_snapshot &&
			( static_cast< SIZE_T >( rva ) + chunk ) <= object->snapshot_size;

		object->stats.granule_count += 1;

		if ( !NT_SUCCESS ( walk_nt ) || walk.status != page_walk_success ) {
			switch ( walk.status ) {
				case page_walk_not_present:
					if ( object->stats.not_present != MAXULONG ) object->stats.not_present += 1;
					record_anomaly ( object , rva , static_cast< ULONG >( chunk ) , page_anomaly_not_present , walk.status );
					break;
				case page_walk_physical_read_failure:
					if ( object->stats.unreadable != MAXULONG ) object->stats.unreadable += 1;
					record_anomaly ( object , rva , static_cast< ULONG >( chunk ) , page_anomaly_unreadable , walk.status );
					break;
				default:
					if ( object->stats.skipped != MAXULONG ) object->stats.skipped += 1;
					record_anomaly ( object , rva , static_cast< ULONG >( chunk ) , page_anomaly_skipped , walk.status );
					break;
			}
		}
		else {
			saw_resident_page = TRUE;
			switch ( walk.level ) {
				case page_mapping_pde_2mb:
					if ( object->stats.present_2mb != MAXULONG ) object->stats.present_2mb += 1;
					if ( object->stats.large_page_backed != MAXULONG ) object->stats.large_page_backed += 1;
					break;
				case page_mapping_pdpte_1gb:
					if ( object->stats.present_1gb != MAXULONG ) object->stats.present_1gb += 1;
					if ( object->stats.large_page_backed != MAXULONG ) object->stats.large_page_backed += 1;
					break;
				default:
					if ( object->stats.present_4kb != MAXULONG ) object->stats.present_4kb += 1;
					break;
			}

			if ( in_snapshot ) {
				SIZE_T copied = 0;
				NTSTATUS copy_status = memory::copy_physical_memory (
					walk.resolved_physical_address ,
					static_cast< PUCHAR >( object->image_snapshot ) + rva ,
					chunk ,
					&copied );
				if ( !NT_SUCCESS ( copy_status ) || copied != chunk ) {
					if ( object->stats.copy_failed != MAXULONG ) object->stats.copy_failed += 1;
					record_anomaly ( object , rva , static_cast< ULONG >( chunk ) , page_anomaly_copy_failed , walk.status );
				}
			}
		}

		va += chunk;
	}

	if ( !saw_resident_page && object->scan_status == driver_scan_ok )
		object->scan_status = driver_scan_race_or_unmapped;

	*result = object;
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS scan_all_drivers ( const driver_scan_options_t* options , driver_scan_set_t** set ) {
	if ( !set ) return STATUS_INVALID_PARAMETER;
	*set = nullptr;

	driver_scan_options_t local_options = options ? *options : default_scan_options ( );

	if ( !page_walk_is_initialized ( ) ) {
		NTSTATUS init = initialize_driver_scan ( );
		if ( !NT_SUCCESS ( init ) ) return init;
	}

	ULONG64 dtb = 0;
	NTSTATUS status = get_system_directory_table_base ( &dtb );
	if ( !NT_SUCCESS ( status ) ) return status;

	AUX_MODULE_EXTENDED_INFO* raw_modules = nullptr;
	ULONG module_count = 0;
	ULONG raw_bytes = 0;
	status = enumerate_loaded_modules ( &raw_modules , &module_count , &raw_bytes );
	if ( !NT_SUCCESS ( status ) ) return status;

	driver_scan_set_t* scan_set = static_cast< driver_scan_set_t* >(
		allocate_nonpaged ( sizeof ( driver_scan_set_t ) , PW_POOL_TAG_SCAN ) );
	if ( !scan_set ) {
		free_pool ( raw_modules , PW_POOL_TAG_SCAN );
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	scan_set->directory_table_base = dtb;
	if ( module_count ) {
		SIZE_T pointer_bytes = 0;
		if ( !mul_size ( module_count , sizeof ( driver_scan_result_t* ) , &pointer_bytes ) ) {
			free_pool ( raw_modules , PW_POOL_TAG_SCAN );
			destroy_scan_set ( &scan_set );
			return STATUS_INTEGER_OVERFLOW;
		}
		scan_set->modules = static_cast< driver_scan_result_t** >(
			allocate_nonpaged ( pointer_bytes , PW_POOL_TAG_SCAN ) );
		if ( !scan_set->modules ) {
			free_pool ( raw_modules , PW_POOL_TAG_SCAN );
			destroy_scan_set ( &scan_set );
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	// copy identifying information out of the AuxKlib snapshot, then free it
	// BEFORE walking pages. expensive physical reads must not run against a
	// stale module-list lock, and AuxKlib itself is not held across the walk.
	struct module_identity_t {
		ULONG64 base;
		ULONG size;
		WCHAR path [ 260 ];
	};

	module_identity_t* identities = nullptr;
	if ( module_count ) {
		SIZE_T id_bytes = 0;
		if ( !mul_size ( module_count , sizeof ( module_identity_t ) , &id_bytes ) ) {
			free_pool ( raw_modules , PW_POOL_TAG_SCAN );
			destroy_scan_set ( &scan_set );
			return STATUS_INTEGER_OVERFLOW;
		}
		identities = static_cast< module_identity_t* >( allocate_nonpaged ( id_bytes , PW_POOL_TAG_SCAN ) );
		if ( !identities ) {
			free_pool ( raw_modules , PW_POOL_TAG_SCAN );
			destroy_scan_set ( &scan_set );
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	for ( ULONG i = 0; i < module_count; ++i ) {
		identities [ i ].base = reinterpret_cast< ULONG64 >( raw_modules [ i ].BasicInfo.ImageBase );
		identities [ i ].size = raw_modules [ i ].ImageSize;
		copy_ansi_to_wide ( raw_modules [ i ].FullPathName ,
							identities [ i ].path ,
							RTL_NUMBER_OF ( identities [ i ].path ) );
	}

	free_pool ( raw_modules , PW_POOL_TAG_SCAN );
	raw_modules = nullptr;

	SIZE_T remaining_budget = local_options.max_total_snapshot_bytes;
	ULONG produced = 0;

	for ( ULONG i = 0; i < module_count; ++i ) {
		driver_scan_result_t* one = nullptr;
		NTSTATUS one_status = scan_driver_module ( dtb ,
												   identities [ i ].base ,
												   identities [ i ].size ,
												   identities [ i ].path ,
												   &local_options ,
												   &remaining_budget ,
												   &one );

		if ( !NT_SUCCESS ( one_status ) || !one ) {
			DbgPrint ( "[pagewalk] skipping module base=0x%llx size=0x%x status=%08x\n" ,
					   identities [ i ].base ,
					   identities [ i ].size ,
					   one_status );
			continue;
		}

		scan_set->modules [ produced++ ] = one;
		scan_set->total_snapshot_bytes += one->snapshot_size;
	}

	free_pool ( identities , PW_POOL_TAG_SCAN );
	scan_set->count = produced;
	*set = scan_set;
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID print_scan_summary ( const driver_scan_set_t* set ) {
	if ( !set ) {
		DbgPrint ( "[pagewalk] scan set is NULL\n" );
		return;
	}

	DbgPrint ( "[pagewalk] modules=%lu dtb=0x%llx snapshot_bytes=%llu\n" ,
			   set->count ,
			   set->directory_table_base ,
			   static_cast< ULONG64 >( set->total_snapshot_bytes ) );

	for ( ULONG i = 0; i < set->count; ++i ) {
		const driver_scan_result_t* m = set->modules [ i ];
		if ( !m ) continue;

		DbgPrint ( "[pagewalk] %ws base=0x%llx size=0x%llx pe=%08x scan=%lu 4k=%lu 2m=%lu 1g=%lu np=%lu unread=%lu copyfail=%lu skip=%lu large=%lu snap=0x%llx\n" ,
				   m->file_name [ 0 ] != L'\0' ? m->file_name : L"(unnamed)" ,
				   m->dll_base ,
				   static_cast< ULONG64 >( m->image_size ) ,
				   m->pe_status ,
				   static_cast< ULONG >( m->scan_status ) ,
				   m->stats.present_4kb ,
				   m->stats.present_2mb ,
				   m->stats.present_1gb ,
				   m->stats.not_present ,
				   m->stats.unreadable ,
				   m->stats.copy_failed ,
				   m->stats.skipped ,
				   m->stats.large_page_backed ,
				   static_cast< ULONG64 >( m->snapshot_size ) );
	}
}
