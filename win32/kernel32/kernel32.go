package kernel32

import (
	"syscall"
	"unsafe"
	"win32"

	"github.com/0xrawsec/golang-utils/log"
)

// CloseHandle Win32 API wrapper
func CloseHandle(hObject win32.HANDLE) error {
	r1, _, lastErr := closeHandle.Call(
		uintptr(hObject))
	if r1 != 0 {
		return nil
	}
	return lastErr
}

func CreateEvent(lpEventAttribute uintptr,
	bManualReset win32.BOOL,
	bInitialState win32.BOOL,
	lpName string) (win32.HANDLE, error) {
	bLpName := []byte(lpName)
	r1, _, lastErr := createEventA.Call(lpEventAttribute,
		uintptr(bManualReset),
		uintptr(bInitialState),
		uintptr(unsafe.Pointer(&bLpName)))
	if r1 == win32.NULL {
		return win32.HANDLE(r1), lastErr
	}
	return win32.HANDLE(r1), nil
}

// CreateToolhelp32Snapshot Win32 API wrapper
func CreateToolhelp32Snapshot(dwFlags win32.DWORD, th32ProcessID win32.DWORD) (win32.HANDLE, error) {
	r1, _, lastErr := createToolhelp32Snapshot.Call(
		uintptr(dwFlags),
		uintptr(th32ProcessID))
	log.Debug(lastErr)
	if win32.LONG_PTR(r1) != win32.INVALID_HANDLE {
		return win32.HANDLE(r1), nil
	}
	return win32.HANDLE(r1), lastErr
}

func EnumProcessModules(hProcess win32.HANDLE) ([]win32.HANDLE, error) {
	var hMods [1024]win32.HANDLE
	needed := win32.DWORD(0)
	_, _, err := k32EnumProcessModules.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&hMods)),
		uintptr(len(hMods)),
		uintptr(unsafe.Pointer(&needed)))
	if err.(syscall.Errno) == 0 {
		// Number of hModules returned
		n := (uintptr(needed) / unsafe.Sizeof(win32.HANDLE(0)))
		return hMods[:n], nil
	}
	return hMods[:], err
}

func Process32FirstW(hSnapshot win32.HANDLE, lppe LPPROCESSENTRY32W) (bool, error) {
	_, _, lastErr := process32FirstW.Call(
		uintptr(hSnapshot),
		uintptr(unsafe.Pointer(lppe)))
	if lastErr.(syscall.Errno) == 0 {
		return true, nil
	}
	return false, lastErr
}

// Thread32First Win32 API wrapper
func Thread32First(hSnapshot win32.HANDLE, lpte LPTHREADENTRY32) (bool, error) {
	_, _, lastErr := thread32First.Call(
		uintptr(hSnapshot),
		uintptr(unsafe.Pointer(lpte)))
	if lastErr.(syscall.Errno) == 0 {
		return true, nil
	}
	return false, lastErr
}

// Thread32Next Win32 API wrapper
func Thread32Next(hSnapshot win32.HANDLE, lpte LPTHREADENTRY32) (bool, error) {
	_, _, lastErr := thread32First.Call(
		uintptr(hSnapshot),
		uintptr(unsafe.Pointer(lpte)))
	if lastErr.(syscall.Errno) == 0 {
		return true, nil
	}
	return false, lastErr
}

// GetExitCodeProcess win32 API wrapper
// hProcess must have the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION
func GetExitCodeProcess(hProcess win32.HANDLE) (exitCode win32.DWORD, err error) {
	rc, _, err := getExitCodeProcess.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&exitCode)))
	// return FALSE if failed
	if win32.BOOL(rc) == win32.FALSE {
		return
	}
	return exitCode, nil
}

// GetCurrentProcess Win32 API wrapper
func GetCurrentProcess() (pseudoHandle win32.HANDLE, lastError error) {
	pHUint, _, _ := getCurrentProcess.Call()
	pseudoHandle = win32.HANDLE(pHUint)
	return pseudoHandle, nil
}

// GetLastError win32 API wrapper
func GetLastError() win32.DWORD {
	r1, _, _ := getLastError.Call()
	return win32.DWORD(r1)
}

// GetProcessIdOfThread win32 API wrapper
func GetProcessIdOfThread(hThread win32.HANDLE) (win32.DWORD, error) {
	r1, _, lastErr := getProcessIdOfThread.Call(uintptr(hThread))
	if r1 == 0 {
		return 0, lastErr
	}
	return win32.DWORD(r1), nil
}

// GetThreadContext Win32 API wrapper
func GetThreadContext(hThread win32.HANDLE, lpContext win32.LPCONTEXT) error {
	r1, _, lastErr := getThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(lpContext)))
	// If function succeed output is not ZERO
	if r1 != win32.NULL {
		return nil
	}
	return lastErr
}

// GetModuleHandleW Win32 API wrapper
func GetModuleHandleW(lpModuleName string) (win32.HANDLE, error) {
	us, err := syscall.UTF16PtrFromString(lpModuleName)
	if err != nil {
		return win32.HANDLE(win32.NULL), err
	}
	r1, _, lastErr := getModuleHandleW.Call(uintptr(unsafe.Pointer(us)))
	if r1 == win32.NULL {
		return win32.HANDLE(win32.NULL), lastErr
	}
	return win32.HANDLE(r1), nil
}

// GetModuleFilename Win32 API wrapper
func GetModuleFilename(hProcess win32.HANDLE) (string, error) {
	var buf [win32.MAX_PATH]uint16
	n := win32.DWORD(len(buf))
	_, _, lastErr := getModuleFileNameW.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(n))
	if lastErr.(syscall.Errno) == 0 {
		return syscall.UTF16ToString(buf[:n]), nil
	}
	return "", lastErr
}

// GetModuleFilenameExW Win32 API wrapper
func GetModuleFilenameExW(hProcess win32.HANDLE, hModule win32.HANDLE) (string, error) {
	var buf [win32.MAX_PATH]uint16
	n := win32.DWORD(len(buf))
	_, _, lastErr := k32GetModuleFileNameExW.Call(
		uintptr(hProcess),
		uintptr(hModule),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(n))
	if lastErr.(syscall.Errno) == 0 {
		return syscall.UTF16ToString(buf[:]), nil
	}
	return "", lastErr
}

// GetModuleInformation Win32 API wrapper
// Calling process needs PROCESS_QUERY_INFORMATION and VM_READ
func GetModuleInformation(hProcess win32.HANDLE, hModule win32.HANDLE) (MODULEINFO, error) {
	mi := MODULEINFO{}
	_, _, err := k32GetModuleInformation.Call(
		uintptr(hProcess),
		uintptr(hModule),
		uintptr(unsafe.Pointer(&mi)),
		uintptr(win32.DWORD(unsafe.Sizeof(mi))))
	if err.(syscall.Errno) != 0 {
		return mi, err
	}
	return mi, nil
}

// QueryFullProcessImageName Win32 API wrapper
func QueryFullProcessImageName(hProcess win32.HANDLE) (string, error) {
	var buf [win32.MAX_PATH]uint16
	n := win32.DWORD(len(buf))
	_, _, lastErr := queryFullProcessImageNameW.Call(
		uintptr(hProcess),
		uintptr(0),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&n)))
	if lastErr.(syscall.Errno) == 0 {
		return syscall.UTF16ToString(buf[:n]), nil
	}
	return "", lastErr
}

// SetThreadContext Win32 API wrapper
func SetThreadContext(hThread win32.HANDLE, lpContext win32.LPCONTEXT) error {
	r1, _, lastErr := setThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(lpContext)))
	// If function succeed output is not ZERO
	if r1 != win32.NULL {
		return nil
	}
	return lastErr
}

// OpenThread Win32 api wrapper
func OpenThread(dwDesiredAccess win32.DWORD, bInheritHandle win32.BOOL, dwThreadId win32.DWORD) (win32.HANDLE, error) {
	r1, _, lastErr := openThread.Call(uintptr(dwDesiredAccess),
		uintptr(bInheritHandle),
		uintptr(dwThreadId))
	if r1 == win32.NULL {
		return win32.HANDLE(0), lastErr
	}
	return win32.HANDLE(r1), nil
}

// OpenProcess Win32 API wrapper
func OpenProcess(dwDesiredAccess win32.DWORD, bInheritHandle win32.BOOL, dwProcessId win32.DWORD) (win32.HANDLE, error) {
	r1, _, lastErr := openProcess.Call(uintptr(dwDesiredAccess),
		uintptr(bInheritHandle),
		uintptr(dwProcessId))
	if r1 == win32.NULL {
		return win32.HANDLE(0), lastErr
	}
	return win32.HANDLE(r1), nil
}

// ReadProcessMemory Win32 API wrapper
// TODO: verify that we have everything
func ReadProcessMemory(hProcess win32.HANDLE, lpBaseAddress win32.LPCVOID, lpBuffer []byte) (int, error) {
	const bufSize = 4096
	var tmpBuf [bufSize]byte
	var read int
	lpNumberOfBytesRead := win32.SIZE_T(0)
	mod := len(lpBuffer) % bufSize
	nSize := bufSize
	for read = 0; read < len(lpBuffer); read += nSize {
		if len(lpBuffer)-read < bufSize {
			nSize = mod
		}
		r1, _, lastErr := readProcessMemory.Call(
			uintptr(hProcess),
			uintptr(lpBaseAddress+win32.LPCVOID(read)),
			//uintptr(unsafe.Pointer(&lpBuffer)),
			uintptr(unsafe.Pointer(&tmpBuf)),
			//uintptr(len(lpBuffer)),
			uintptr(nSize),
			uintptr(unsafe.Pointer(&lpNumberOfBytesRead)))
		// if error, we return
		if r1 == 0 {
			return read + int(lpNumberOfBytesRead), lastErr
		}
		copy(lpBuffer[read:], tmpBuf[:nSize])
	}
	return read, nil
}

// WriteProcessMemory Win32 API wrapper
// TODO: write test
func WriteProcessMemory(hProcess win32.HANDLE, lpBaseAddress win32.LPCVOID, lpBuffer []byte) (int, error) {
	const bufSize = 4096
	var tmpBuf [bufSize]byte
	var lpNumberOfBytesWritten = win32.SIZE_T(0)
	written := 0
	for written < len(lpBuffer) {
		var src []byte
		// Maybe need <=
		if written+bufSize < len(lpBuffer) {
			src = lpBuffer[written : written+bufSize]
		} else {
			src = lpBuffer[written:]
		}
		nSize := copy(tmpBuf[:], src)
		r1, _, lastErr := writeProcessMemory.Call(
			uintptr(hProcess),
			uintptr(lpBaseAddress+win32.LPCVOID(written)),
			uintptr(unsafe.Pointer(&tmpBuf)),
			uintptr(nSize),
			uintptr(unsafe.Pointer(&lpNumberOfBytesWritten)))
		if r1 == 0 {
			return written + int(lpNumberOfBytesWritten), lastErr
		}
		written += int(lpNumberOfBytesWritten)
	}
	return written, nil
}

// SuspendThread Win32 API wrapper
func SuspendThread(hThread win32.HANDLE) (win32.DWORD, error) {
	r1, _, lastErr := suspendThread.Call(uintptr(hThread))
	if lastErr.(syscall.Errno) != 0 {
		return 0, lastErr
	}
	return win32.DWORD(r1), nil
}

// ResumeThread Win32 API wrapper
func ResumeThread(hThread win32.HANDLE) (win32.DWORD, error) {
	r1, _, lastErr := resumeThread.Call(uintptr(hThread))
	if lastErr.(syscall.Errno) != 0 {
		return 0, lastErr
	}
	return win32.DWORD(r1), nil
}

// ResetEvent Win32 API wrapper
func ResetEvent(hEvent win32.HANDLE) error {
	r1, _, lastErr := resetEvent.Call(uintptr(hEvent))
	if win32.BOOL(r1) == win32.FALSE {
		return lastErr
	}
	return nil
}

func TerminateProcess(hProcess win32.HANDLE, exitCode win32.UINT) (err error) {
	_, _, err = terminateProcess.Call(uintptr(hProcess), uintptr(exitCode))
	if err.(syscall.Errno) != 0 {
		return err
	}
	return nil
}

// VirtualProtect Win32 API wrapper
func VirtualProtect(lpAddress win32.LPVOID, dwSize win32.SIZE_T, flNewProtect win32.DWORD) (lpflOldProtect win32.DWORD, err error) {
	r1, _, lastErr := virtualProtect.Call(uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flNewProtect),
		uintptr(unsafe.Pointer(&lpflOldProtect)))
	if r1 == 0 {
		return 0, lastErr
	}
	return lpflOldProtect, nil
}

// VirtualQueryEx Win32 API wrapper
func VirtualQueryEx(hProcess win32.HANDLE, lpAddress win32.LPCVOID) (win32.MemoryBasicInformation, error) {
	mbi := win32.MemoryBasicInformation{}
	r1, _, lastErr := virtualQueryEx.Call(
		uintptr(hProcess),
		uintptr(lpAddress),
		uintptr(unsafe.Pointer(&mbi)),
		uintptr(unsafe.Sizeof(mbi)))
	if r1 == 0 {
		return mbi, lastErr
	}
	return mbi, nil
}

// VirtualAllocEx Win32 API wrapper
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890(v=vs.85).aspx
// LPVOID WINAPI VirtualAllocEx(
//_In_     HANDLE hProcess,
//_In_opt_ LPVOID lpAddress,
//_In_     SIZE_T dwSize,
//_In_     DWORD  flAllocationType,
//_In_     DWORD  flProtect
//);
// TODO: Test it
func VirtualAllocEx(hProcess win32.HANDLE, lpAddress win32.LPVOID, dwSize win32.SIZE_T,
	flAllocationType win32.DWORD, flProtect win32.DWORD) (win32.LPVOID, error) {
	r1, _, lastErr := virtualAllocEx.Call(uintptr(hProcess),
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flAllocationType),
		uintptr(flProtect))
	if r1 == win32.NULL {
		return win32.LPVOID(r1), lastErr
	}
	return win32.LPVOID(r1), nil
}

func WaitForSingleObject(hHandle win32.HANDLE, dwMilliseconds win32.DWORD) win32.DWORD {
	r1, _, _ := waitForSingleObject.Call(uintptr(hHandle), uintptr(dwMilliseconds))
	return win32.DWORD(r1)
}
