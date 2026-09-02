#pragma once

#include <ntddk.h>
#include <ntintsafe.h>
#include <ntstrsafe.h>
#include <intrin.h>

#if !defined(_M_AMD64)
#error pagewalk supports 64-bit long-mode paging only. ARM64 and x86 are not implemented.
#endif

// x64 long mode (4-level paging; 5-level / LA57 is detected and walked).
// Windows 8.1+ for MmCopyMemory. Windows 10 16299+ matches the INF target.
// pool allocation uses ExAllocatePool2 when NTDDI_VERSION >= NTDDI_WIN10_VB,
// otherwise NonPagedPoolNx with explicit zeroing.

#define PW_POOL_TAG_MEM  'mewP'
#define PW_POOL_TAG_WALK 'lkwP'
#define PW_POOL_TAG_PE   'epwP'
#define PW_POOL_TAG_SCAN 'cswP'

#define PW_MAX_SINGLE_ALLOC ( ( SIZE_T ) 0x20000000 )

#ifndef BooleanFlagOn
#define BooleanFlagOn(F, SF) ( ( BOOLEAN ) ( ( ( F ) & ( SF ) ) != 0 ) )
#endif

#ifndef STATUS_PARTIAL_COPY
#define STATUS_PARTIAL_COPY ( ( NTSTATUS ) 0x8000000DL )
#endif

#ifndef STATUS_INVALID_IMAGE_NOT_MZ
#define STATUS_INVALID_IMAGE_NOT_MZ ( ( NTSTATUS ) 0xC000012FL )
#endif

_IRQL_requires_max_ ( DISPATCH_LEVEL )
inline PVOID allocate_nonpaged ( _In_ SIZE_T size , _In_ ULONG tag ) {
	if ( !size || size > PW_MAX_SINGLE_ALLOC ) return nullptr;

#if ( NTDDI_VERSION >= NTDDI_WIN10_VB )
	return ExAllocatePool2 ( POOL_FLAG_NON_PAGED , size , tag );
#else
	PVOID buffer = ExAllocatePoolWithTag ( NonPagedPoolNx , size , tag );
	if ( buffer ) RtlZeroMemory ( buffer , size );
	return buffer;
#endif
}

_IRQL_requires_max_ ( DISPATCH_LEVEL )
inline VOID free_pool ( _In_opt_ PVOID buffer , _In_ ULONG tag ) {
	if ( buffer ) ExFreePoolWithTag ( buffer , tag );
}

inline BOOLEAN add_u64 ( _In_ ULONG64 a , _In_ ULONG64 b , _Out_ ULONG64* result ) {
	return NT_SUCCESS ( RtlUInt64Add ( a , b , result ) );
}

inline BOOLEAN add_ptr ( _In_ ULONG_PTR a , _In_ ULONG_PTR b , _Out_ ULONG_PTR* result ) {
	return NT_SUCCESS ( RtlULongPtrAdd ( a , b , result ) );
}

inline BOOLEAN add_size ( _In_ SIZE_T a , _In_ SIZE_T b , _Out_ SIZE_T* result ) {
	return NT_SUCCESS ( RtlSizeTAdd ( a , b , result ) );
}

inline BOOLEAN mul_size ( _In_ SIZE_T a , _In_ SIZE_T b , _Out_ SIZE_T* result ) {
	return NT_SUCCESS ( RtlSizeTMult ( a , b , result ) );
}

inline SIZE_T bytes_to_end_of_page ( _In_ ULONG64 address ) {
	ULONG64 offset = address & ( PAGE_SIZE - 1 );
	return static_cast< SIZE_T >( PAGE_SIZE - offset );
}
