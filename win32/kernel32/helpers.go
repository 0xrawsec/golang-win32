package kernel32

import (
	"encoding/json"
	"os"
	"syscall"

	"fmt"
	"reflect"
	"win32"

	"github.com/0xrawsec/golang-utils/log"
)

func ToJSON(data interface{}) string {
	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// AllVirtualQueryEx helper function
func AllVirtualQueryEx(hProcess win32.HANDLE) (cmbi chan win32.MemoryBasicInformation) {
	cmbi = make(chan win32.MemoryBasicInformation)
	go func() {
		defer close(cmbi)
		lpAddress := win32.LPCVOID(0)
		for {
			var mbi win32.MemoryBasicInformation
			mbi, err := VirtualQueryEx(hProcess, lpAddress)
			if err != nil {
				break
			}
			lpAddress += win32.LPCVOID(mbi.RegionSize)
			cmbi <- mbi
		}
	}()
	return
}

// ForceDumpAllMemory helper function
// TODO : increase the limitation used to dump memory
func ForceDumpAllMemory(pid int, dumpFile string) error {
	// Open out file
	f, err := os.Create(dumpFile)
	if err != nil {
		return err
	}
	// Open the process with appropriate access rights
	da := uint32(PROCESS_ALL_ACCESS)
	hProcess, err := syscall.OpenProcess(da, false, uint32(pid))
	if err != nil {
		return err
	}
	defer CloseHandle(win32.HANDLE(hProcess))

	for mbi := range AllVirtualQueryEx(win32.HANDLE(hProcess)) {
		// Filter by size
		if mbi.RegionSize < (1 << 25) {
			mem := make([]byte, mbi.RegionSize)
			lpAddress := win32.LPCVOID(mbi.BaseAddress)
			ReadProcessMemory(win32.HANDLE(hProcess), lpAddress, mem)
			f.Write(mem)
		}
	}
	return nil
}

// GetModuleFilenameSelf helper function to retrieve self executable module
// filename
func GetModuleFilenameSelf() (string, error) {
	lpFilename := make([]uint16, win32.MAX_PATH)
	_, err := GetModuleFilename(0, lpFilename)
	if err != nil {
		return "", err
	}
	return syscall.UTF16ToString(lpFilename), err
}

// GetModuleFilenameFromPID helper function to retrieve the module filename from
// a pid
func GetModuleFilenameFromPID(pid int) (fn string, err error) {
	// Open the process with appropriate access rights
	da := uint32(PROCESS_QUERY_LIMITED_INFORMATION)
	hProcess, err := syscall.OpenProcess(da, false, uint32(pid))
	if err != nil {
		return
	}
	lpFilename := make([]uint16, win32.MAX_PATH)
	_, err = QueryFullProcessImageName(win32.HANDLE(hProcess), lpFilename)
	if err != nil {
		return
	}
	return syscall.UTF16ToString(lpFilename), err
}

// ListThreads list the threads of process pid
func ListThreads(pid int) (ctid chan int) {
	ctid = make(chan int)
	go func() {
		defer close(ctid)
		for i := 0; i < 20000; i++ {
			hThread, err := OpenThread(THREAD_QUERY_LIMITED_INFORMATION, win32.FALSE, win32.DWORD(i))
			if err == nil {
				ppid, err := GetProcessIdOfThread(hThread)
				if err != nil {
					log.LogError(err)
				}
				if int(ppid) == pid {
					ctid <- i
				}
				CloseHandle(hThread)
			}
		}
	}()
	return
}

// SuspendProcess suspends a given process
func SuspendProcess(pid int) {
	for tid := range ListThreads(pid) {
		hThread, err := OpenThread(THREAD_SUSPEND_RESUME, win32.FALSE, win32.DWORD(tid))
		if err != nil {
			log.LogError(err)
		} else {
			_, err := SuspendThread(hThread)
			if err != nil {
				log.LogError(err)
			}
		}
		CloseHandle(hThread)
	}
}

// ResumeProcess resumes a previously suspended process
func ResumeProcess(pid int) {
	for tid := range ListThreads(pid) {
		hThread, err := OpenThread(THREAD_SUSPEND_RESUME, win32.FALSE, win32.DWORD(tid))
		if err != nil {
			log.LogError(err)
		} else {
			_, err := ResumeThread(hThread)
			if err != nil {
				log.LogError(err)
			}
		}
		CloseHandle(hThread)
	}
}

// WriteMemoryAndControl write a buffer in memory and control it has been
// properly written. This function also manages the memory protections.
func WriteMemoryAndControl(hProcess win32.HANDLE, lpBaseAddress win32.LPCVOID, lpBuffer []byte) error {
	checkBuf := make([]byte, len(lpBuffer))
	// Changing memory protection
	op, err := VirtualProtect(win32.LPVOID(lpBaseAddress), win32.SIZE_T(len(lpBuffer)), win32.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return err
	}
	// Writing Memory
	w, err := WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer)
	if err != nil {
		return err
	}
	// Control that we wrote the good number of bytes
	if w != len(lpBuffer) {
		return fmt.Errorf("Partial write only")
	}
	// Control what has been read
	r, err := ReadProcessMemory(hProcess, lpBaseAddress, checkBuf)
	if err != nil {
		return err
	}
	if r != len(lpBuffer) {
		return fmt.Errorf("Partial read only")
	}
	// We compare what we have written with what we have read
	if !reflect.DeepEqual(lpBuffer, checkBuf) {
		return fmt.Errorf("Data copy failed")
	}
	// Changing back the memory protections
	log.Debugf("Restoring memory protections: 0x%04x", op)
	rwep, err := VirtualProtect(win32.LPVOID(lpBaseAddress), win32.SIZE_T(len(lpBuffer)), op)
	if err != nil {
		return err
	}
	if rwep != win32.PAGE_EXECUTE_READWRITE {
		return fmt.Errorf("Cannot change memory protection")
	}
	return nil
}
