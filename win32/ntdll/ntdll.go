// +build windows

package ntdll

import (
	"syscall"
	"unsafe"

	"github.com/0xrawsec/golang-win32/win32"
)

// NtStatusToError convert an ntstatus error code to a Go error
func NtStatusToError(ntstatus uintptr) error {
	if ntstatus == win32.STATUS_SUCCESS {
		return nil
	}
	return syscall.Errno(RtlNtStatusToDosError(ntstatus))
}

// RtlNtStatusToDosError wrapper
func RtlNtStatusToDosError(ntstatus uintptr) uint32 {
	r1, _, _ := rtlNtStatusToDosError.Call(ntstatus)
	return uint32(r1)
}

// InitializeObjectAttribute macro
func InitializeObjectAttribute(name *UNICODE_STRING, attr win32.ULONG, root win32.HANDLE) (initializedAttributes *OBJECT_ATTRIBUTES) {
	/* VOID InitializeObjectAttributes(
	   [out]          POBJECT_ATTRIBUTES   InitializedAttributes,
	   [in]           PUNICODE_STRING      ObjectName,
	   [in]           ULONG                Attributes,
	   [in]           HANDLE               RootDirectory,
	   [in, optional] PSECURITY_DESCRIPTOR SecurityDescriptor
	 );*/
	initializedAttributes = &OBJECT_ATTRIBUTES{}
	initializedAttributes.ObjectName = name
	initializedAttributes.Attributes = attr
	initializedAttributes.RootDirectory = root
	initializedAttributes.SecurityDescriptor = 0
	return initializedAttributes
}

// RtlInitUnicodeString wrapper
func RtlInitUnicodeString(src string) (dest *UNICODE_STRING) {
	/* void RtlInitUnicodeString(
	   PUNICODE_STRING DestinationString,
	   PCWSTR          SourceString
	 ); */
	dest = &UNICODE_STRING{}
	rtlInitUnicodeString.Call(
		uintptr(unsafe.Pointer(dest)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(src))),
	)
	return dest
}

// NtOpenFile wrapper
func NtOpenFile(
	accessMask win32.ACCESS_MASK,
	objectAttributes *OBJECT_ATTRIBUTES,
	ioStatusBlock *IO_STATUS_BLOCK,
	shareAccess win32.ULONG,
	openOptions win32.ULONG) (fileHandle win32.HANDLE, err error) {

	/*__kernel_entry NTSTATUS NtOpenFile(
	  OUT PHANDLE           FileHandle,
	  IN ACCESS_MASK        DesiredAccess,
	  IN POBJECT_ATTRIBUTES ObjectAttributes,
	  OUT PIO_STATUS_BLOCK  IoStatusBlock,
	  IN ULONG              ShareAccess,
	  IN ULONG              OpenOptions
	);*/

	ntstatus, _, _ := ntOpenFile.Call(
		uintptr(unsafe.Pointer(&fileHandle)),
		uintptr(accessMask),
		uintptr(unsafe.Pointer(objectAttributes)),
		uintptr(unsafe.Pointer(ioStatusBlock)),
		uintptr(shareAccess),
		uintptr(openOptions),
	)

	err = NtStatusToError(ntstatus)
	return
}

// ZwSetInformationFile wrapper
func ZwSetInformationFile(fileHandle win32.HANDLE, ioStatusBlock *IO_STATUS_BLOCK, fileInformation win32.PVOID, length win32.ULONG, fileInformationClass uintptr) error {
	/* __kernel_entry NTSYSCALLAPI NTSTATUS NtSetInformationFile(
	   HANDLE                 FileHandle,
	   PIO_STATUS_BLOCK       IoStatusBlock,
	   PVOID                  FileInformation,
	   ULONG                  Length,
	   FILE_INFORMATION_CLASS FileInformationClass
	 );*/

	ntstatus, _, _ := ntSetInformationFile.Call(
		uintptr(fileHandle),
		uintptr(unsafe.Pointer(ioStatusBlock)),
		uintptr(fileInformation),
		uintptr(length),
		fileInformationClass,
	)
	return NtStatusToError(ntstatus)
}

// NtQueryInformationProcess Win32 API wrapper
// TODO: test it
func NtQueryInformationProcess(hProcess win32.HANDLE,
	processInfoClass win32.DWORD,
	processInfo win32.PVOID,
	processInfoLength win32.ULONG,
	returnLength win32.ULONG_PTR) error {
	r1, _, lastErr := ntQueryInformationProcess.Call(
		uintptr(hProcess),
		uintptr(processInfoClass),
		uintptr(processInfo),
		uintptr(processInfoLength),
		uintptr(returnLength))
	if r1 == 0 {
		return nil
	}
	return lastErr
}

// NtUnmapViewOfSection Win32 API wrapper
// https://msdn.microsoft.com/en-us/library/windows/hardware/ff567119(v=vs.85).aspx
// TODO: test it
func NtUnmapViewOfSection(hProcess win32.HANDLE, baseAddress win32.PVOID) error {
	r1, _, lastError := ntUnmapViewOfSection.Call(uintptr(hProcess), uintptr(baseAddress))
	if r1 == 0 {
		return nil
	}
	return lastError
}

/*
RtlIpv6AddressToStringW API wrapper generated from prototype
NTSYSAPI PWSTR RtlIpv6AddressToStringW(
	  const in6_addr *Addr,
	 PWSTR S );
*/
func RtlIpv6AddressToStringW(
	addr *In6Addr,
	s *uint16) *uint16 {
	r1, _, _ := rtlIpv6AddressToStringW.Call(
		uintptr(unsafe.Pointer(addr)),
		uintptr(unsafe.Pointer(s)))
	return (*uint16)(unsafe.Pointer(r1))
}

/*
RtlIpv6AddressToStringExW API wrapper generated from prototype
NTSYSAPI NTSTATUS RtlIpv6AddressToStringExW(
	  const in6_addr *Address,
	 ULONG ScopeId,
	 USHORT Port,
	 PWSTR AddressString,
	 PULONG AddressStringLength );
*/
func RtlIpv6AddressToStringExW(
	address *In6Addr,
	scopeId uint32,
	port uint16,
	addressString *uint16,
	addressStringLength *uint32) error {
	ntstatus, _, _ := rtlIpv6AddressToStringExW.Call(
		uintptr(unsafe.Pointer(address)),
		uintptr(scopeId),
		uintptr(port),
		uintptr(unsafe.Pointer(addressString)),
		uintptr(unsafe.Pointer(addressStringLength)))
	return NtStatusToError(ntstatus)
}
