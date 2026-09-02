#pragma once

#include "Common.hpp"

namespace memory {

	// IRQL: APC_LEVEL or below. MmCopyMemory is not legal at DISPATCH_LEVEL.
	// destination must be a resident kernel buffer. STATUS_SUCCESS is returned
	// only when the full size is copied; partial copies are treated as failure.

	// virtual_address is the virtual address of the memory to copy, size is the number of bytes to copy,
	// and destination is the buffer to copy the memory to.
	_IRQL_requires_max_ ( APC_LEVEL )
	NTSTATUS copy_virtual_memory ( _In_ ULONG_PTR virtual_address ,
								   _Out_writes_bytes_ ( size ) PVOID destination ,
								   _In_ SIZE_T size ,
								   _Out_opt_ PSIZE_T bytes_copied );

	// physical_address is the physical address of the memory to copy, size is the number of bytes to copy,
	// and destination is the buffer to copy the memory to. physical address 0 is a valid source.
	_IRQL_requires_max_ ( APC_LEVEL )
	NTSTATUS copy_physical_memory ( _In_ ULONG64 physical_address ,
									_Out_writes_bytes_ ( size ) PVOID destination ,
									_In_ SIZE_T size ,
									_Out_opt_ PSIZE_T bytes_copied );

	// virtual_address is the virtual address of the page to copy, destination is the buffer to copy the page to.
	_IRQL_requires_max_ ( APC_LEVEL )
	NTSTATUS copy_virtual_page ( _In_ ULONG_PTR virtual_address ,
								 _Out_writes_bytes_ ( PAGE_SIZE ) PVOID destination );

	// physical_address is the physical address of the page to copy, destination is the buffer to copy the page to.
	_IRQL_requires_max_ ( APC_LEVEL )
	NTSTATUS copy_physical_page ( _In_ ULONG64 physical_address ,
								  _Out_writes_bytes_ ( PAGE_SIZE ) PVOID destination );

} // namespace memory
