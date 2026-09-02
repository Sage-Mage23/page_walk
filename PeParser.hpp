#pragma once

#include "Common.hpp"
#include <ntimage.h>

// PE parser for in-memory kernel images.
// IRQL: APC_LEVEL or below (reads go through the physical page-table walker).
// the image is treated as untrusted and concurrently mutable. headers are copied
// into a private nonpaged buffer before any field is inspected.

static const ULONG k_pe_max_header_bytes = 0x10000;
static const USHORT k_pe_max_sections = 96;
static const ULONG k_pe_max_image_size = 0x10000000;

struct pe_section_info_t {
	CHAR name [ IMAGE_SIZEOF_SHORT_NAME + 1 ];
	ULONG virtual_address;
	ULONG virtual_size;
	ULONG size_of_raw_data;
	ULONG pointer_to_raw_data;
	ULONG characteristics;
};

struct pe_header_info_t {
	BOOLEAN is_64_bit;
	USHORT machine;
	USHORT number_of_sections;
	USHORT number_of_rva_and_sizes;
	USHORT size_of_optional_header;
	USHORT subsystem;
	USHORT dll_characteristics;
	ULONG characteristics;
	ULONG time_date_stamp;
	ULONG checksum;
	ULONG size_of_image;
	ULONG size_of_headers;
	ULONG address_of_entry_point;
	ULONG section_alignment;
	ULONG file_alignment;
	ULONG64 image_base_from_optional_header;
	pe_section_info_t sections [ 96 ];
};

_IRQL_requires_max_ ( APC_LEVEL )
VOID reset_pe_header_info ( _Out_ pe_header_info_t* out );

// directory_table_base / module_base / image_size identify the in-memory image.
// out receives copied PE metadata. no pointers into the live mapping are returned.
_IRQL_requires_max_ ( APC_LEVEL )
NTSTATUS read_pe_header ( _In_ ULONG64 directory_table_base ,
						  _In_ ULONG64 module_base ,
						  _In_ SIZE_T image_size ,
						  _Out_ pe_header_info_t* out );
