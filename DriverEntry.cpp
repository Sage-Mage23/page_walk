#include "DriverScanner.hpp"
#include "PageWalker.hpp"

static driver_scan_set_t* g_scan_set = nullptr;

extern "C" DRIVER_UNLOAD pagewalk_unload;

_Use_decl_annotations_
extern "C" VOID pagewalk_unload ( PDRIVER_OBJECT driver_object ) {
	UNREFERENCED_PARAMETER ( driver_object );
	destroy_scan_set ( &g_scan_set );
}

static VOID print_single_module_example ( _In_ const driver_scan_result_t* module_info ) {
	if ( !module_info ) return;

	DbgPrint ( "[pagewalk] example module %ws\n" , module_info->file_name );
	DbgPrint ( "[pagewalk]   DllBase            = 0x%llx\n" , module_info->dll_base );
	DbgPrint ( "[pagewalk]   ImageSize          = 0x%llx\n" , static_cast< ULONG64 >( module_info->image_size ) );
	DbgPrint ( "[pagewalk]   Machine            = 0x%04x  sections=%u  timestamp=%08x  checksum=%08x\n" ,
			   module_info->pe.machine ,
			   module_info->pe.number_of_sections ,
			   module_info->pe.time_date_stamp ,
			   module_info->pe.checksum );
	DbgPrint ( "[pagewalk]   Subsystem          = %u  DllCharacteristics=0x%04x\n" ,
			   module_info->pe.subsystem ,
			   module_info->pe.dll_characteristics );
	DbgPrint ( "[pagewalk]   ScanStatus         = %lu  PeStatus=%08x\n" ,
			   static_cast< ULONG >( module_info->scan_status ) ,
			   module_info->pe_status );
	DbgPrint ( "[pagewalk]   granules           = %lu\n" , module_info->stats.granule_count );
	DbgPrint ( "[pagewalk]     present 4K       = %lu\n" , module_info->stats.present_4kb );
	DbgPrint ( "[pagewalk]     present 2M       = %lu (4K granules inside 2MB pages)\n" , module_info->stats.present_2mb );
	DbgPrint ( "[pagewalk]     present 1G       = %lu\n" , module_info->stats.present_1gb );
	DbgPrint ( "[pagewalk]     large-page backed= %lu\n" , module_info->stats.large_page_backed );
	DbgPrint ( "[pagewalk]     not present      = %lu\n" , module_info->stats.not_present );
	DbgPrint ( "[pagewalk]     unreadable PT    = %lu\n" , module_info->stats.unreadable );
	DbgPrint ( "[pagewalk]     copy failed      = %lu\n" , module_info->stats.copy_failed );
	DbgPrint ( "[pagewalk]     skipped          = %lu\n" , module_info->stats.skipped );
	DbgPrint ( "[pagewalk]   snapshot           = %p  bytes=0x%llx  anomalies=%lu\n" ,
			   module_info->image_snapshot ,
			   static_cast< ULONG64 >( module_info->snapshot_size ) ,
			   module_info->anomaly_count );

	ULONG show = ( module_info->anomaly_count < 8 ) ? module_info->anomaly_count : 8;
	for ( ULONG i = 0; i < show; ++i ) {
		const page_anomaly_t* a = &module_info->anomalies [ i ];
		DbgPrint ( "[pagewalk]     anomaly[%lu] rva=0x%x size=0x%x kind=%lu walk=%lu\n" ,
				   i ,
				   a->rva ,
				   a->size ,
				   static_cast< ULONG >( a->kind ) ,
				   static_cast< ULONG >( a->walk_status ) );
	}
}

_Use_decl_annotations_
extern "C" NTSTATUS DriverEntry ( PDRIVER_OBJECT driver_object , PUNICODE_STRING registry_path ) {
	UNREFERENCED_PARAMETER ( registry_path );

	driver_object->DriverUnload = pagewalk_unload;

	NTSTATUS status = initialize_driver_scan ( );
	if ( !NT_SUCCESS ( status ) ) {
		DbgPrint ( "[pagewalk] initialize failed %08x\n" , status );
		return status;
	}

	DbgPrint ( "[pagewalk] paging: current CR3=0x%llx  initialized=%d  5-level=%d\n" ,
			   read_current_cr3 ( ) ,
			   page_walk_is_initialized ( ) ? 1 : 0 ,
			   page_walk_uses_five_level ( ) ? 1 : 0 );

	ULONG64 system_dtb = 0;
	status = get_system_directory_table_base ( &system_dtb );
	if ( NT_SUCCESS ( status ) )
		DbgPrint ( "[pagewalk] system DirectoryTableBase=0x%llx\n" , system_dtb );

	driver_scan_options_t options = default_scan_options ( );

	status = scan_all_drivers ( &options , &g_scan_set );
	if ( !NT_SUCCESS ( status ) ) {
		DbgPrint ( "[pagewalk] scan_all_drivers failed %08x\n" , status );
		return status;
	}

	print_scan_summary ( g_scan_set );

	if ( g_scan_set ) {
		ULONG_PTR self = reinterpret_cast< ULONG_PTR >( driver_object->DriverStart );
		const driver_scan_result_t* example = nullptr;

		for ( ULONG i = 0; i < g_scan_set->count; ++i ) {
			const driver_scan_result_t* candidate = g_scan_set->modules [ i ];
			if ( candidate && candidate->dll_base == static_cast< ULONG64 >( self ) ) {
				example = candidate;
				break;
			}
		}

		if ( !example && g_scan_set->count ) example = g_scan_set->modules [ 0 ];
		print_single_module_example ( example );
	}

	return STATUS_SUCCESS;
}
