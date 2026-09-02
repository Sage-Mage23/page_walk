#include "PhysicalMemory.hpp"

namespace memory {

	static NTSTATUS copy_memory_internal ( _In_ MM_COPY_ADDRESS source ,
										   _In_ ULONG flags ,
										   _Out_writes_bytes_ ( size ) PVOID destination ,
										   _In_ SIZE_T size ,
										   _Out_opt_ PSIZE_T bytes_copied ) {
		if ( bytes_copied ) *bytes_copied = 0;
		if ( !destination || !size ) return STATUS_INVALID_PARAMETER;

		SIZE_T transferred = 0;
		NTSTATUS status = MmCopyMemory ( destination , source , size , flags , &transferred );

		if ( bytes_copied ) *bytes_copied = transferred;
		if ( !NT_SUCCESS ( status ) ) return status;
		if ( transferred != size ) return STATUS_PARTIAL_COPY;

		return STATUS_SUCCESS;
	}

	_Use_decl_annotations_
	NTSTATUS copy_virtual_memory ( ULONG_PTR virtual_address ,
								   PVOID destination ,
								   SIZE_T size ,
								   PSIZE_T bytes_copied ) {
		if ( !virtual_address ) {
			if ( bytes_copied ) *bytes_copied = 0;
			return STATUS_INVALID_PARAMETER;
		}

		ULONG_PTR end = 0;
		if ( !add_ptr ( virtual_address , size , &end ) ) {
			if ( bytes_copied ) *bytes_copied = 0;
			return STATUS_INTEGER_OVERFLOW;
		}

		MM_COPY_ADDRESS mm_copy_address_t = { };
		mm_copy_address_t.VirtualAddress = reinterpret_cast< PVOID >( virtual_address );

		return copy_memory_internal ( mm_copy_address_t , MM_COPY_MEMORY_VIRTUAL , destination , size , bytes_copied );
	}

	_Use_decl_annotations_
	NTSTATUS copy_physical_memory ( ULONG64 physical_address ,
									PVOID destination ,
									SIZE_T size ,
									PSIZE_T bytes_copied ) {
		ULONG64 end = 0;
		if ( !add_u64 ( physical_address , static_cast< ULONG64 >( size ) , &end ) ) {
			if ( bytes_copied ) *bytes_copied = 0;
			return STATUS_INTEGER_OVERFLOW;
		}

		MM_COPY_ADDRESS mm_copy_address_t = { };
		mm_copy_address_t.PhysicalAddress.QuadPart = static_cast< LONGLONG >( physical_address );

		return copy_memory_internal ( mm_copy_address_t , MM_COPY_MEMORY_PHYSICAL , destination , size , bytes_copied );
	}

	_Use_decl_annotations_
	NTSTATUS copy_virtual_page ( ULONG_PTR virtual_address , PVOID destination ) {
		SIZE_T copied = 0;
		return copy_virtual_memory ( virtual_address & ~static_cast< ULONG_PTR >( PAGE_SIZE - 1 ) ,
									 destination ,
									 PAGE_SIZE ,
									 &copied );
	}

	_Use_decl_annotations_
	NTSTATUS copy_physical_page ( ULONG64 physical_address , PVOID destination ) {
		SIZE_T copied = 0;
		return copy_physical_memory ( physical_address & ~static_cast< ULONG64 >( PAGE_SIZE - 1 ) ,
									  destination ,
									  PAGE_SIZE ,
									  &copied );
	}

} // namespace memory
