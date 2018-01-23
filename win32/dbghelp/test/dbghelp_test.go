package main

import (
	"os"
	"syscall"
	"testing"
	"win32"
	"win32/dbghelp"
	"win32/kernel32"
)

func TestMiniDumpWriteDump(t *testing.T) {
	outfile := "minidump.dmp"
	// Fork process first because not good idea to minidump the current process
	// It does not work to minidump a process created with CREATE_SUSPENDED flag
	name, err := syscall.UTF16PtrFromString(`C:\Windows\System32\cmd.exe`)
	if err != nil {
		panic(err)
	}
	si := new(syscall.StartupInfo)
	pi := new(syscall.ProcessInformation)
	t.Logf("Creating new process: %s", os.Args[0])
	err = syscall.CreateProcess(name, nil, nil, nil, false, win32.CREATE_NO_WINDOW, nil, nil, si, pi)
	if err != nil {
		panic(err)
	}
	defer func() {
		syscall.TerminateProcess(pi.Process, 0)
	}()

	os.Remove(outfile)

	// Define the outfile
	hFile, err := syscall.Open(outfile, syscall.O_RDWR|syscall.O_CREAT, 0777)
	if err != nil {
		panic(err)
	}

	// Get proper process accesses
	pid := uint32(pi.ProcessId)
	//da := uint32(kernel32.PROCESS_ALL_ACCESS | kernel32.PROCESS_VM_READ | kernel32.PROCESS_QUERY_INFORMATION | kernel32.PROCESS_DUP_HANDLE)
	da := uint32(kernel32.PROCESS_ALL_ACCESS)
	hProcess, err := syscall.OpenProcess(da, false, pid)
	if err != nil {
		panic(err)
	}

	// Now we can do the minidump
	err = dbghelp.MiniDumpWriteDump(win32.HANDLE(hProcess),
		win32.DWORD(pid),
		win32.HANDLE(hFile),
		dbghelp.MiniDumpWithFullMemory)

	if err != nil {
		panic(err)
	}
}
