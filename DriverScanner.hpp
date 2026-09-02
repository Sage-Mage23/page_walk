#pragma once

#include "Common.hpp"
#include "PageWalker.hpp"
#include "PeParser.hpp"

// loaded-module enumerator and read-only image scanner.
//
// IRQL:
// - initialize_driver_scan / scan_all_drivers: PASSIVE_LEVEL (AuxKlib).
// - scan_driver_module / destroy_*: APC_LEVEL or below.
//
// ownership: scan_all_drivers / scan_driver_module allocate a result object.
// the caller owns it and must call the matching destroy function, including on
// failure paths where a non-NULL pointer was returned. destroy functions free
// nested buffers and null the caller's pointer.
//
// the scanner never holds a module-list lock while walking pages. the list is
// snapshotted, then each image is inspected independently.

static const SIZE_T k_default_max_snapshot_per_module = 0x01000000;
static const SIZE_T k_default_max_total_snapshot = 0x04000000;
static const ULONG k_default_max_anomalies_per_module = 512;

enum driver_scan_status_t {
	driver_scan_ok = 0 ,
	driver_scan_invalid_range ,
	driver_scan_pe_parse_failed ,
	driver_scan_allocation_failed ,
	driver_scan_snapshot_budget_exhausted ,
	driver_scan_race_or_unmapped ,
	driver_scan_unsupported_paging
};

enum page_anomaly_kind_t {
	page_anomaly_not_present = 0 ,
	page_anomaly_unreadable ,
	page_anomaly_copy_failed ,
	page_anomaly_skipped ,
	page_anomaly_large_page_backed
};

struct driver_scan_options_t {
	BOOLEAN capture_image_snapshot;
	BOOLEAN record_anomalies;
	SIZE_T max_snapshot_per_module;
	SIZE_T max_total_snapshot_bytes;
	ULONG max_anomalies_per_module;
};

struct page_anomaly_t {
	ULONG rva;
	ULONG size;
	page_anomaly_kind_t kind;
	page_walk_status_t walk_status;
};

struct module_page_stats_t {
	// counts are 4 KB granules, not architected page-table entries.
	ULONG granule_count;
	ULONG present_4kb;
	ULONG present_2mb;
	ULONG present_1gb;
	ULONG large_page_backed;
	ULONG not_present;
	ULONG unreadable;
	ULONG copy_failed;
	ULONG skipped;
};

struct driver_scan_result_t {
	ULONG64 dll_base;
	SIZE_T image_size;
	SIZE_T snapshot_size;
	WCHAR full_path [ 260 ];
	WCHAR file_name [ 64 ];
	driver_scan_status_t scan_status;
	NTSTATUS pe_status;
	pe_header_info_t pe;
	module_page_stats_t stats;
	PVOID image_snapshot;
	page_anomaly_t* anomalies;
	ULONG anomaly_count;
	ULONG anomaly_capacity;
};

struct driver_scan_set_t {
	ULONG count;
	ULONG64 directory_table_base;
	SIZE_T total_snapshot_bytes;
	driver_scan_result_t** modules;
};

inline driver_scan_options_t default_scan_options ( ) {
	driver_scan_options_t options = { };
	options.capture_image_snapshot = TRUE;
	options.record_anomalies = TRUE;
	options.max_snapshot_per_module = k_default_max_snapshot_per_module;
	options.max_total_snapshot_bytes = k_default_max_total_snapshot;
	options.max_anomalies_per_module = k_default_max_anomalies_per_module;
	return options;
}

_IRQL_requires_max_ ( PASSIVE_LEVEL )
NTSTATUS initialize_driver_scan ( );

_IRQL_requires_max_ ( PASSIVE_LEVEL )
NTSTATUS scan_all_drivers ( _In_opt_ const driver_scan_options_t* options ,
							_Outptr_ driver_scan_set_t** set );

_IRQL_requires_max_ ( APC_LEVEL )
NTSTATUS scan_driver_module ( _In_ ULONG64 directory_table_base ,
							  _In_ ULONG64 image_base ,
							  _In_ SIZE_T image_size ,
							  _In_opt_ PCWSTR full_path ,
							  _In_ const driver_scan_options_t* options ,
							  _Inout_opt_ PSIZE_T remaining_snapshot_budget ,
							  _Outptr_ driver_scan_result_t** result );

_IRQL_requires_max_ ( APC_LEVEL )
VOID destroy_scan_result ( _Inout_ driver_scan_result_t** result );

_IRQL_requires_max_ ( APC_LEVEL )
VOID destroy_scan_set ( _Inout_ driver_scan_set_t** set );

_IRQL_requires_max_ ( APC_LEVEL )
VOID print_scan_summary ( _In_opt_ const driver_scan_set_t* set );
