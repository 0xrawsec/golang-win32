package dbghelp

import (
	"syscall"
	"win32"
	"win32/kernel32"
)

// MiniDumpWriteDump Win32 API wrapper, the three last args are skipped for the moment
func MiniDumpWriteDump(hProcess win32.HANDLE, ProcessId win32.DWORD,
	hFile win32.HANDLE, DumpType win32.DWORD) error {
	r1, _, lastErr := miniDumpWriteDump.Call(uintptr(hProcess), uintptr(ProcessId),
		uintptr(hFile), uintptr(DumpType), win32.NULL, win32.NULL, win32.NULL)
	// If function succeed output is TRUE
	if r1 == uintptr(win32.TRUE) {
		return nil
	}
	return lastErr
}

//////////////////////////////// Helpers ///////////////////////////////////////

// FullMemoryMiniDump helper function to create a FullMemoryMinidump of a process identified by pid
func FullMemoryMiniDump(pid int, dumpFile string) error {
	// Define the outfile
	hFile, err := syscall.Open(dumpFile, syscall.O_RDWR|syscall.O_CREAT, 0700)
	if err != nil {
		return err
	}
	defer syscall.Close(hFile)

	// Open the process with appropriate access rights
	da := uint32(kernel32.PROCESS_ALL_ACCESS)
	hProcess, err := syscall.OpenProcess(da, false, uint32(pid))
	if err != nil {
		return err
	}
	// Now we can do the minidump
	err = MiniDumpWriteDump(
		win32.HANDLE(hProcess), // Process Handle
		win32.DWORD(pid),       // PID of process to dump
		win32.HANDLE(hFile),    // Dump file Handle
		MiniDumpWithFullMemory) // Minidump type
	return err
}
