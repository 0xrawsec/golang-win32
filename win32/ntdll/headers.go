package ntdll

import "github.com/0xrawsec/golang-win32/win32"

type PROCESS_BASIC_INFORMATION struct {
	ExitStatus                   win32.NTSTATUS
	PebBaseAddress               win32.PPEB
	AffinityMask                 win32.KAFFINITY
	BasePriority                 win32.KPRIORITY
	UniqueProcessId              win32.ULONG_PTR
	InheritedFromUniqueProcessId win32.ULONG_PTR
}
