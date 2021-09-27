package main

import (
	"encoding/json"
	"os"
	"syscall"
	"testing"
	"time"
	"win32"
	"win32/kernel32"

	"github.com/0xrawsec/golang-utils/log"
)

var (
	NULL = win32.NULL
)

func ToJSON(data interface{}) string {
	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func init() {
	log.InitLogger(log.LDebug)
}

func TestGetThreadContext(t *testing.T) {
	t.Log("Entering test")
	//name, err := syscall.UTF16PtrFromString(os.Args[0])
	name, err := syscall.UTF16PtrFromString("C:\\Windows\\System32\\cmd.exe")
	if err != nil {
		panic(err)
	}
	si := new(syscall.StartupInfo)
	pi := new(syscall.ProcessInformation)
	t.Logf("Creating new process: %s", os.Args[0])
	syscall.CreateProcess(name, nil, nil, nil, false, win32.CREATE_SUSPENDED|win32.CREATE_NEW_CONSOLE, nil, nil, si, pi)
	defer func() {
		syscall.TerminateProcess(pi.Process, 0)
	}()

	ctx := new(win32.CONTEXT)
	ctx.ContextFlags = win32.CONTEXT_FULL
	t.Log(ToJSON(ctx))
	err = kernel32.GetThreadContext(win32.HANDLE(pi.Thread), ctx)
	if err != nil {
		panic(err)
	}
	t.Logf("Thread context: %s", string(ToJSON(ctx)))

	if err = kernel32.SetThreadContext(win32.HANDLE(pi.Thread), ctx); err != nil {
		panic(err)
	}

	if _, err = kernel32.ResumeThread(win32.HANDLE(pi.Thread)); err != nil {
		panic(err)
	}
	log.Debug("Sleeping")
	time.Sleep(10 * time.Second)
	t.Log(ToJSON(ctx))
}

func TestVirtualQueryEx(t *testing.T) {
	hProcess, _ := kernel32.GetCurrentProcess()
	mbi, err := kernel32.VirtualQueryEx(hProcess, win32.LPCVOID(0))
	if err != nil {
		panic(err)
	}
	t.Log(ToJSON(mbi))
}

func TestAllVirtualQueryEx(t *testing.T) {
	hProcess, _ := kernel32.GetCurrentProcess()
	for mbi := range kernel32.AllVirtualQueryEx(hProcess) {
		t.Log(ToJSON(mbi))
	}
}

func TestReadProcessMemory(t *testing.T) {
	name, err := syscall.UTF16PtrFromString(os.Args[0])
	if err != nil {
		panic(err)
	}
	si := new(syscall.StartupInfo)
	pi := new(syscall.ProcessInformation)
	t.Logf("Creating new process: %s", os.Args[0])
	syscall.CreateProcess(name, nil, nil, nil, false, win32.CREATE_SUSPENDED, nil, nil, si, pi)
	defer func() {
		syscall.TerminateProcess(pi.Process, 0)
	}()

	//hProcess, _ := kernel32.GetCurrentProcess()
	/*hProcess := win32.HANDLE(pi.Process)
	for mbi := range kernel32.AllVirtualQueryEx(hProcess) {
		log.Debugf("Attempting to read: %d", mbi.RegionSize)
		//mem := make([]byte, mbi.RegionSize, mbi.RegionSize)
		mem := make([]byte, 4096, 4096)
		//var buff [4096]byte
		//r, err := kernel32.ReadProcessMemory(hProcess, win32.LPCVOID(mbi.BaseAddress), buff[:])
		r, err := kernel32.ReadProcessMemory(hProcess, win32.LPCVOID(mbi.BaseAddress), mem)
		//mem = append(mem, buff[:]...)
		log.Debugf("Read: %d", r)
		if err != nil {
			t.Logf("Read: %d, Err: %s", r, err.Error())
		} else {
			t.Logf("Read: %d", r)
		}
	}*/
	kernel32.ForceDumpAllMemory(int(pi.ProcessId), "memory.dmp")
}

func TestThreadFirst32(t *testing.T) {
	snap, err := kernel32.CreateToolhelp32Snapshot(win32.DWORD(kernel32.TH32CS_SNAPALL), win32.DWORD(0))
	if err != nil {
		t.Error(err)
		return
	}
	defer kernel32.CloseHandle(snap)
	te := kernel32.NewThreadEntry32()
	ok, err := kernel32.Thread32First(snap, &te)
	if !ok {
		t.Error(err)
		return
	}
	for ok, _ := kernel32.Thread32Next(snap, &te); ok; {
		log.Debug(ToJSON(te))
		ok, _ = kernel32.Thread32Next(snap, &te)
	}
}
func TestProcessFirst32(t *testing.T) {
	pid := 0
	snap, err := kernel32.CreateToolhelp32Snapshot(win32.DWORD(kernel32.TH32CS_SNAPALL), win32.DWORD(pid))
	if err != nil {
		t.Error(err)
		return
	}
	defer kernel32.CloseHandle(snap)
	pe := kernel32.NewProcessEntry32W()
	ok, err := kernel32.Process32FirstW(snap, &pe)
	if !ok {
		t.Error(err)
		return
	}
	log.Debug(ToJSON(pe))
}

func TestListThreads(t *testing.T) {
	for tid := range kernel32.ListThreads(os.Getpid()) {
		t.Log(tid)
	}
}

func TestSuspendResumeProcess(t *testing.T) {
	pid := 5552
	sleep := 10 * time.Second
	kernel32.SuspendProcess(pid)
	log.Infof("Process %d suspended for %s, try to interact with it", pid, sleep)
	time.Sleep(sleep)
	log.Infof("Resuming %d", pid)
	kernel32.ResumeProcess(pid)

}

func TestEnumProcessModules(t *testing.T) {
	hProcess, _ := kernel32.GetCurrentProcess()
	modules, err := kernel32.EnumProcessModules(hProcess)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	t.Log(modules)
	for _, hMod := range modules {
		modName, err := kernel32.GetModuleFilenameExW(hProcess, hMod)
		if err != nil {
			t.Log(err)
			t.FailNow()
		}
		t.Log(modName)
		modInfo, err := kernel32.GetModuleInformation(hProcess, hMod)
		if err != nil {
			t.Log(err)
			t.FailNow()
		}
		t.Log(modInfo)
	}
}

func TestGetModuleInfoFromPid(t *testing.T) {
	image := "C:\\Windows\\System32\\calc.exe"
	kernel32.FindTextSectionFromImage(image)
	name, err := syscall.UTF16PtrFromString("C:\\Windows\\System32\\calc.exe")
	if err != nil {
		panic(err)
	}
	si := new(syscall.StartupInfo)
	pi := new(syscall.ProcessInformation)
	t.Logf("Creating process: %s", image)
	syscall.CreateProcess(name, nil, nil, nil, false, win32.CREATE_NEW_CONSOLE, nil, nil, si, pi)
	if !kernel32.WaitThreadRuns(win32.HANDLE(pi.Thread), time.Second*5, time.Millisecond*100) {
		t.Log("Main thread did not run in a decent amount of time")
		t.FailNow()
	}
	time.Sleep(time.Millisecond * 500)
	mi, err := kernel32.GetImageModuleInfoFromPID(pi.ProcessId)
	if err != nil {
		t.Logf("Cannot retrieve ModuleInfo from pid: %s", err)
		t.FailNow()
	}
	t.Logf("Module Information: %s", mi)
	text, err := kernel32.FindTextSection(win32.HANDLE(pi.Process), mi)
	if err != nil {
		t.Logf("Cannot get text section")
		t.FailNow()
	}
	t.Logf("Text section of binary: %s", text)
	bdiff, _, err := kernel32.CheckProcessIntegrity(win32.HANDLE(pi.Process))
	if err != nil {
		t.Logf("Cannot check process integrity")
		t.FailNow()
	}
	t.Logf("Integrity check: %d", bdiff)
	if bdiff > 0 {
		t.FailNow()
	}
	kernel32.TerminateProcess(win32.HANDLE(pi.Process), 0)
}

func TestQueryDosDevice(t *testing.T) {
	devs, err := kernel32.QueryDosDevice("")
	if err != nil {
		t.Logf("Failed with error: %s", err)
		t.Fail()
	}
	for _, dev := range devs {
		d, _ := kernel32.QueryDosDevice(dev)
		t.Logf("%s: %v", dev, d)
	}

}
