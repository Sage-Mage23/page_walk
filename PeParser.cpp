#include "PeParser.hpp"
#include "PageWalker.hpp"

static BOOLEAN in_range ( _In_ SIZE_T offset , _In_ SIZE_T field_size , _In_ SIZE_T buffer_size ) {
	SIZE_T end = 0;
	if ( !add_size ( offset , field_size , &end ) ) return FALSE;
	return end <= buffer_size;
}

static NTSTATUS read_headers ( _In_ ULONG64 directory_table_base ,
							   _In_ ULONG64 image_base ,
							   _In_ SIZE_T claimed_image_size ,
							   _Outptr_result_bytebuffer_ ( *buffer_size ) PVOID* buffer ,
							   _Out_ PSIZE_T buffer_size ) {
	*buffer = nullptr;
	*buffer_size = 0;

	SIZE_T first_read = PAGE_SIZE;
	if ( claimed_image_size && claimed_image_size < first_read ) first_read = claimed_image_size;
	if ( first_read < sizeof ( IMAGE_DOS_HEADER ) ) return STATUS_INVALID_IMAGE_FORMAT;

	PVOID local = allocate_nonpaged ( k_pe_max_header_bytes , PW_POOL_TAG_PE );
	if ( !local ) return STATUS_INSUFFICIENT_RESOURCES;

	SIZE_T bytes_read = 0;
	SIZE_T bytes_skipped = 0;
	NTSTATUS status = read_virtual_range ( directory_table_base ,
										   image_base ,
										   local ,
										   first_read ,
										   &bytes_read ,
										   &bytes_skipped );

	if ( bytes_skipped || bytes_read != first_read ) {
		free_pool ( local , PW_POOL_TAG_PE );
		return NT_SUCCESS ( status ) ? STATUS_PARTIAL_COPY : status;
	}

	PIMAGE_DOS_HEADER dos = static_cast< PIMAGE_DOS_HEADER >( local );
	if ( dos->e_magic != IMAGE_DOS_SIGNATURE ) {
		free_pool ( local , PW_POOL_TAG_PE );
		return STATUS_INVALID_IMAGE_NOT_MZ;
	}

	if ( dos->e_lfanew < 0 ) {
		free_pool ( local , PW_POOL_TAG_PE );
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	// pull the rest of the header region (up to 64 KB). SizeOfHeaders and the
	// section table live beyond IMAGE_NT_HEADERS64; copying only 264 bytes after e_lfanew is not enough.
	SIZE_T need = k_pe_max_header_bytes;
	if ( claimed_image_size && claimed_image_size < need ) need = claimed_image_size;
	if ( need < first_read ) need = first_read;

	if ( need > first_read ) {
		bytes_read = 0;
		bytes_skipped = 0;
		status = read_virtual_range ( directory_table_base ,
									  image_base ,
									  local ,
									  need ,
									  &bytes_read ,
									  &bytes_skipped );
		if ( bytes_skipped || bytes_read != need ) {
			free_pool ( local , PW_POOL_TAG_PE );
			return NT_SUCCESS ( status ) ? STATUS_PARTIAL_COPY : status;
		}
		first_read = need;
	}

	*buffer = local;
	*buffer_size = first_read;
	return STATUS_SUCCESS;
}

static NTSTATUS parse_from_buffer ( _In_reads_bytes_ ( buffer_size ) PVOID buffer ,
									_In_ SIZE_T buffer_size ,
									_Out_ pe_header_info_t* out ) {
	reset_pe_header_info ( out );

	if ( !in_range ( 0 , sizeof ( IMAGE_DOS_HEADER ) , buffer_size ) )
		return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_DOS_HEADER dos = static_cast< PIMAGE_DOS_HEADER >( buffer );
	if ( dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 )
		return STATUS_INVALID_IMAGE_FORMAT;

	SIZE_T lfanew = static_cast< SIZE_T >( dos->e_lfanew );
	if ( !in_range ( lfanew , sizeof ( ULONG ) + sizeof ( IMAGE_FILE_HEADER ) , buffer_size ) )
		return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_NT_HEADERS nt = reinterpret_cast< PIMAGE_NT_HEADERS >(
		static_cast< PUCHAR >( buffer ) + lfanew );

	if ( nt->Signature != IMAGE_NT_SIGNATURE )
		return STATUS_INVALID_IMAGE_FORMAT;

	IMAGE_FILE_HEADER file_header = nt->FileHeader;
	SIZE_T opt_off = lfanew + FIELD_OFFSET ( IMAGE_NT_HEADERS32 , OptionalHeader );
	SIZE_T opt_size = file_header.SizeOfOptionalHeader;

	if ( opt_size < sizeof ( USHORT ) || !in_range ( opt_off , opt_size , buffer_size ) )
		return STATUS_INVALID_IMAGE_FORMAT;

	USHORT magic = *reinterpret_cast< PUSHORT >( static_cast< PUCHAR >( buffer ) + opt_off );
	BOOLEAN is_64 = FALSE;

	ULONG size_of_image = 0;
	ULONG size_of_headers = 0;
	ULONG checksum = 0;
	ULONG entry_point = 0;
	ULONG section_align = 0;
	ULONG file_align = 0;
	ULONG64 optional_image_base = 0;
	USHORT subsystem = 0;
	USHORT dll_characteristics = 0;
	USHORT number_of_rva_and_sizes = 0;

	if ( magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ) {
		if ( file_header.Machine != IMAGE_FILE_MACHINE_I386 )
			return STATUS_INVALID_IMAGE_FORMAT;
		if ( opt_size < FIELD_OFFSET ( IMAGE_OPTIONAL_HEADER32 , DataDirectory ) )
			return STATUS_INVALID_IMAGE_FORMAT;

		IMAGE_OPTIONAL_HEADER32 opt32 = { };
		SIZE_T copy_opt = ( opt_size < sizeof ( opt32 ) ) ? opt_size : sizeof ( opt32 );
		RtlCopyMemory ( &opt32 , static_cast< PUCHAR >( buffer ) + opt_off , copy_opt );

		size_of_image = opt32.SizeOfImage;
		size_of_headers = opt32.SizeOfHeaders;
		checksum = opt32.CheckSum;
		entry_point = opt32.AddressOfEntryPoint;
		section_align = opt32.SectionAlignment;
		file_align = opt32.FileAlignment;
		optional_image_base = opt32.ImageBase;
		subsystem = opt32.Subsystem;
		dll_characteristics = opt32.DllCharacteristics;
		number_of_rva_and_sizes = static_cast< USHORT >( opt32.NumberOfRvaAndSizes );
		is_64 = FALSE;
	}
	else if ( magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ) {
		if ( file_header.Machine != IMAGE_FILE_MACHINE_AMD64 &&
			 file_header.Machine != IMAGE_FILE_MACHINE_ARM64 )
			return STATUS_INVALID_IMAGE_FORMAT;
		if ( opt_size < FIELD_OFFSET ( IMAGE_OPTIONAL_HEADER64 , DataDirectory ) )
			return STATUS_INVALID_IMAGE_FORMAT;

		IMAGE_OPTIONAL_HEADER64 opt64 = { };
		SIZE_T copy_opt = ( opt_size < sizeof ( opt64 ) ) ? opt_size : sizeof ( opt64 );
		RtlCopyMemory ( &opt64 , static_cast< PUCHAR >( buffer ) + opt_off , copy_opt );

		size_of_image = opt64.SizeOfImage;
		size_of_headers = opt64.SizeOfHeaders;
		checksum = opt64.CheckSum;
		entry_point = opt64.AddressOfEntryPoint;
		section_align = opt64.SectionAlignment;
		file_align = opt64.FileAlignment;
		optional_image_base = opt64.ImageBase;
		subsystem = opt64.Subsystem;
		dll_characteristics = opt64.DllCharacteristics;
		number_of_rva_and_sizes = static_cast< USHORT >( opt64.NumberOfRvaAndSizes );
		is_64 = TRUE;
	}
	else {
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	if ( number_of_rva_and_sizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES )
		number_of_rva_and_sizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

	if ( !size_of_image || size_of_image > k_pe_max_image_size )
		return STATUS_INVALID_IMAGE_FORMAT;

	SIZE_T section_off = opt_off + opt_size;
	USHORT section_count = file_header.NumberOfSections;
	if ( section_count > k_pe_max_sections ) section_count = k_pe_max_sections;

	SIZE_T section_bytes = 0;
	if ( !mul_size ( section_count , sizeof ( IMAGE_SECTION_HEADER ) , &section_bytes ) ||
		 !in_range ( section_off , section_bytes , buffer_size ) )
		return STATUS_INVALID_IMAGE_FORMAT;

	out->is_64_bit = is_64;
	out->machine = file_header.Machine;
	out->number_of_sections = section_count;
	out->number_of_rva_and_sizes = number_of_rva_and_sizes;
	out->size_of_optional_header = file_header.SizeOfOptionalHeader;
	out->subsystem = subsystem;
	out->dll_characteristics = dll_characteristics;
	out->characteristics = file_header.Characteristics;
	out->time_date_stamp = file_header.TimeDateStamp;
	out->checksum = checksum;
	out->size_of_image = size_of_image;
	out->size_of_headers = size_of_headers;
	out->address_of_entry_point = entry_point;
	out->section_alignment = section_align;
	out->file_alignment = file_align;
	out->image_base_from_optional_header = optional_image_base;

	PIMAGE_SECTION_HEADER sections = reinterpret_cast< PIMAGE_SECTION_HEADER >(
		static_cast< PUCHAR >( buffer ) + section_off );

	for ( USHORT i = 0; i < section_count; ++i ) {
		IMAGE_SECTION_HEADER sh = sections [ i ];
		RtlCopyMemory ( out->sections [ i ].name , sh.Name , IMAGE_SIZEOF_SHORT_NAME );
		out->sections [ i ].name [ IMAGE_SIZEOF_SHORT_NAME ] = '\0';
		out->sections [ i ].virtual_address = sh.VirtualAddress;
		out->sections [ i ].virtual_size = sh.Misc.VirtualSize;
		out->sections [ i ].size_of_raw_data = sh.SizeOfRawData;
		out->sections [ i ].pointer_to_raw_data = sh.PointerToRawData;
		out->sections [ i ].characteristics = sh.Characteristics;
	}

	return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID reset_pe_header_info ( pe_header_info_t* out ) {
	if ( out ) RtlZeroMemory ( out , sizeof ( *out ) );
}

_Use_decl_annotations_
NTSTATUS read_pe_header ( ULONG64 directory_table_base ,
						  ULONG64 module_base ,
						  SIZE_T image_size ,
						  pe_header_info_t* out ) {
	if ( !out || !module_base ) return STATUS_INVALID_PARAMETER;

	reset_pe_header_info ( out );

	if ( image_size && image_size < sizeof ( IMAGE_DOS_HEADER ) )
		return STATUS_INVALID_IMAGE_FORMAT;

	PVOID buffer = nullptr;
	SIZE_T buffer_size = 0;
	NTSTATUS status = read_headers ( directory_table_base ,
									 module_base ,
									 image_size ,
									 &buffer ,
									 &buffer_size );
	if ( !NT_SUCCESS ( status ) ) return status;

	status = parse_from_buffer ( buffer , buffer_size , out );
	free_pool ( buffer , PW_POOL_TAG_PE );
	return status;
}
