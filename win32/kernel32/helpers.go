//go:build windows
// +build windows

package kernel32

import (
	"debug/pe"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-win32/win32"
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

// FindTextSection returns the Memory Basic Information of the memory
// zone containing the entrypoint of the image
func FindTextSection(hProcess win32.HANDLE, mi MODULEINFO) (mbi win32.MemoryBasicInformation, err error) {
	for address := win32.LPCVOID(mi.LpBaseOfDll); address-win32.LPCVOID(mi.LpBaseOfDll) < win32.LPCVOID(mi.SizeOfImage); {
		mbi, err = VirtualQueryEx(win32.HANDLE(hProcess), address)
		// Entrypoint is in this memory area
		// Explicit casting is needed because MemoryBasicInformation fields
		// have not the same types between architectures
		if win32.ULONGLONG(mi.EntryPoint) > win32.ULONGLONG(mbi.BaseAddress) && win32.ULONGLONG(mi.EntryPoint) < win32.ULONGLONG(mbi.BaseAddress)+win32.ULONGLONG(mbi.RegionSize) {
			return
		}
		address += win32.LPCVOID(mbi.RegionSize)
	}
	return
}

// FindTextSectionFromImage returns the section containing the entrypoint
func FindTextSectionFromImage(image string) (section []byte, err error) {
	// parse the pe file
	var entrypoint uint32
	imPe, err := pe.Open(image)
	if err != nil {
		return
	}
	defer imPe.Close()
	switch imPe.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entrypoint = imPe.OptionalHeader.(*pe.OptionalHeader32).AddressOfEntryPoint
	case *pe.OptionalHeader64:
		entrypoint = imPe.OptionalHeader.(*pe.OptionalHeader64).AddressOfEntryPoint
	}

	for _, s := range imPe.Sections {
		header := s.SectionHeader
		if entrypoint > header.VirtualAddress && entrypoint < header.VirtualAddress+header.Size {
			return s.Data()
		}
	}
	return
}

func max(i, j int) int {
	if i < j {
		return j
	}
	return i
}

func min(i, j int) int {
	if i < j {
		return i
	}
	return j
}

// CheckProcessIntegrity helper function to check process integrity
// compare entrypoint section on disk and in memory
func CheckProcessIntegrity(hProcess win32.HANDLE) (bytediff int, length int, err error) {
	image, err := QueryFullProcessImageName(hProcess)
	if err != nil {
		return 0, 0, fmt.Errorf("Cannot get image of process")
	}
	mi, err := GetImageModuleInfo(hProcess)
	if err != nil {
		return 0, 0, fmt.Errorf("Cannot get module info")
	}
	// We get the text section from memory
	memInfoTextInMem, err := FindTextSection(hProcess, mi)
	if err != nil {
		return 0, 0, fmt.Errorf("Cannot find section in memory")
	}
	textInMem := make([]byte, memInfoTextInMem.RegionSize)
	_, err = ReadProcessMemory(hProcess, win32.LPCVOID(memInfoTextInMem.BaseAddress), textInMem)
	if err != nil {
		return 0, 0, fmt.Errorf("Cannot read process memory")
	}
	textOnDisk, err := FindTextSectionFromImage(image)
	if err != nil {
		return 0, 0, fmt.Errorf("Cannot find section on disk")
	}
	return fastDiff(&textInMem, &textOnDisk), max(len(textOnDisk), len(textInMem)), nil
}

func fastDiff(b1, b2 *[]byte) (diff int) {
	min := min(len(*b1), len(*b2))
	max := max(len(*b1), len(*b2))
	diff = max - min
	for i := 0; i < min; i++ {
		if (*b1)[i] != (*b2)[i] {
			diff++
		}
	}
	return diff
}

// GetModuleFilenameSelf helper function to retrieve self executable module
// filename
func GetModuleFilenameSelf() (string, error) {
	return GetModuleFilename(0)
}

// GetModuleFilenameFromPID helper function to retrieve the module filename from
// a pid
func GetModuleFilenameFromPID(pid int) (fn string, err error) {
	// Open the process with appropriate access rights
	hProcess, err := OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, win32.FALSE, win32.DWORD(pid))
	if err != nil {
		return
	}
	defer CloseHandle(hProcess)
	return QueryFullProcessImageName(win32.HANDLE(hProcess))
}

// ListThreads list the threads of process pid
func ListThreads(pid int) (ctid chan int) {
	ctid = make(chan int, 42)
	go func() {
		defer close(ctid)
		for i := 0; i < 100000; i++ {
			hThread, err := OpenThread(THREAD_QUERY_LIMITED_INFORMATION, win32.FALSE, win32.DWORD(i))
			if err == nil {
				ppid, err := GetProcessIdOfThread(hThread)
				if err != nil {
					log.Error(err)
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

// GetFirstTidOfPid list the threads of process pid
func GetFirstTidOfPid(pid int) int {
	for i := 0; i < 100000; i++ {
		hThread, err := OpenThread(THREAD_QUERY_LIMITED_INFORMATION, win32.FALSE, win32.DWORD(i))
		if err == nil {
			defer CloseHandle(hThread)
			ppid, err := GetProcessIdOfThread(hThread)
			if err != nil {
				log.Error(err)
			}
			if int(ppid) == pid {
				return i
			}
		}
	}
	return -1
}

// IsThreadRunning returns true if hThread is running else false
// It is a little hack since I am not aware of any API call to check
// whether a thread is running or not
func IsThreadRunning(hThread win32.HANDLE) (bool, error) {
	count, err := SuspendThread(hThread)
	if err != nil {
		return false, err
	}
	ResumeThread(hThread)
	return count == 0, nil
}

// IsProcessRunning returns true if the process is running and false if not
func IsProcessRunning(hProcess win32.HANDLE) bool {
	exitCode, err := GetExitCodeProcess(hProcess)
	if err == nil {
		if exitCode == win32.STILL_ACTIVE {
			return true
		}
	}
	return false
}

// IsPIDRunning returns true if the process referenced by pid is running
func IsPIDRunning(pid int) bool {
	if pid == 0 {
		return true
	}
	if pid < 0 {
		return false
	}
	if hProcess, err := OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, win32.FALSE, win32.DWORD(pid)); err == nil {
		defer CloseHandle(hProcess)
		return IsProcessRunning(hProcess)
	}
	return false
}

// WaitThreadRuns waits until a thread is running
func WaitThreadRuns(hThread win32.HANDLE, step, timeout time.Duration) bool {
	for wait := time.Duration(0); wait < timeout; wait += step {
		if ok, _ := IsThreadRunning(hThread); ok {
			return true
		}
		time.Sleep(step)
	}
	return false
}

// GetImageModuleInfo helper function
func GetImageModuleInfo(hProcess win32.HANDLE) (mi MODULEINFO, err error) {
	procImage, err := QueryFullProcessImageName(hProcess)
	if err != nil {
		return
	}
	modules, err := EnumProcessModules(hProcess)
	if err != nil {
		return
	}
	for _, hMod := range modules {
		var modName string
		modName, err = GetModuleFilenameExW(hProcess, hMod)
		if err != nil {
			return
		}
		// need this otherwise we can have issue not finding the module
		if strings.ToLower(modName) == strings.ToLower(procImage) {
			log.Debugf("Found module name: %s", modName)
			mi, err = GetModuleInformation(hProcess, hMod)
			return mi, err
		}
	}
	return mi, fmt.Errorf("Module not found")
}

// GetImageModuleInfoFromPID helper function
func GetImageModuleInfoFromPID(pid uint32) (mi MODULEINFO, err error) {
	// open remote process
	hProcess, err := OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, win32.FALSE, win32.DWORD(pid))
	if err != nil {
		return
	}
	defer CloseHandle(hProcess)
	return GetImageModuleInfo(hProcess)
}

// GetProcessProtectionLevel gives the protection level associated to the process identified by pid
func GetProcessProtectionLevel(pid uint32) (ppli ProcessProtectionLevelInformation, err error) {

	hProcess, err := OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, win32.FALSE, win32.DWORD(pid))
	if err != nil {
		return
	}

	defer CloseHandle(hProcess)

	err = GetProcessInformation(
		syscall.Handle(hProcess),
		ProcessProtectionLevelInfoClass,
		uintptr(unsafe.Pointer(&ppli)),
		uint32(unsafe.Sizeof(ppli)),
	)

	return
}

// SuspendProcess suspends a given process
func SuspendProcess(pid int) {
	if IsPIDRunning(pid) {
		for tid := range ListThreads(pid) {
			hThread, err := OpenThread(THREAD_SUSPEND_RESUME, win32.FALSE, win32.DWORD(tid))
			if err != nil {
				log.Error(err)
			} else {
				_, err := SuspendThread(hThread)
				if err != nil {
					log.Error(err)
				}
			}
			CloseHandle(hThread)
		}
	}
}

// SetCurrentThreadPriority helper function to set priority of current Thread
func SetCurrentThreadPriority(nPriority int) error {
	hThread := GetCurrentThread()
	defer CloseHandle(hThread)
	return SetThreadPriority(hThread, nPriority)
}

// ResumeProcess resumes a previously suspended process
func ResumeProcess(pid int) {
	if IsPIDRunning(pid) {
		for tid := range ListThreads(pid) {
			hThread, err := OpenThread(THREAD_SUSPEND_RESUME, win32.FALSE, win32.DWORD(tid))
			if err != nil {
				log.Error(err)
			} else {
				_, err := ResumeThread(hThread)
				if err != nil {
					log.Error(err)
				}
			}
			CloseHandle(hThread)
		}
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
