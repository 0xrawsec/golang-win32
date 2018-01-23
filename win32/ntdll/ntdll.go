package ntdll

import (
	"win32"
)

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
