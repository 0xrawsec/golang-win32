package advapi32

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/0xrawsec/golang-utils/encoding"
)

var (
	guidRE = regexp.MustCompile(`\{[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}`)
)

func GUIDFromString(guid string) (*GUID, error) {
	g := GUID{}
	guid = strings.ToUpper(guid)
	if !guidRE.MatchString(guid) {
		return nil, fmt.Errorf("Bad GUID format")
	}
	guid = strings.Trim(guid, "{}")
	sp := strings.Split(guid, "-")
	c, _ := strconv.ParseUint(sp[0], 16, 32)
	g.Data1 = uint32(c)
	c, _ = strconv.ParseUint(sp[1], 16, 16)
	g.Data2 = uint16(c)
	c, _ = strconv.ParseUint(sp[2], 16, 16)
	g.Data3 = uint16(c)
	i64, _ := strconv.ParseUint(fmt.Sprintf("%s%s", sp[3], sp[4]), 16, 64)
	buf, err := encoding.Marshal(&i64, binary.BigEndian)
	if err != nil {
		return nil, err
	}
	copy(g.Data4[:], buf)

	return &g, nil
}

/*
StartTraceW API wrapper generated from prototype
EXTERN_C ULONG WMIAPI StartTraceW (
	 PTRACEHANDLE TraceHandle,
	 LPCWSTR InstanceName,
	 PEVENT_TRACE_PROPERTIES Properties);
*/
func StartTrace(traceHandle *uintptr,
	instanceName *uint16,
	properties *EventTraceProperties) error {
	r1, _, _ := startTraceW.Call(
		uintptr(unsafe.Pointer(traceHandle)),
		uintptr(unsafe.Pointer(instanceName)),
		uintptr(unsafe.Pointer(properties)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

/*
EnableTraceEx2 API wrapper generated from prototype
EXTERN_C ULONG WMIAPI EnableTraceEx2 (
	 TRACEHANDLE TraceHandle,
	 LPCGUID ProviderId,
	 ULONG ControlCode,
	 UCHAR Level,
	 ULONGLONG MatchAnyKeyword,
	 ULONGLONG MatchAllKeyword,
	 ULONG Timeout,
	 PENABLE_TRACE_PARAMETERS EnableParameters);
*/
func EnableTraceEx2(traceHandle uintptr,
	providerId *GUID,
	controlCode uint32,
	level uint8,
	matchAnyKeyword uint64,
	matchAllKeyword uint64,
	timeout uint32,
	enableParameters *EnableTraceParameters) error {
	r1, _, _ := enableTraceEx2.Call(
		uintptr(traceHandle),
		uintptr(unsafe.Pointer(providerId)),
		uintptr(controlCode),
		uintptr(level),
		uintptr(matchAnyKeyword),
		uintptr(matchAllKeyword),
		uintptr(timeout),
		uintptr(unsafe.Pointer(enableParameters)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

/*
ProcessTrace API wrapper generated from prototype
EXTERN_C ULONG WMIAPI ProcessTrace (
	 PTRACEHANDLE HandleArray,
	 ULONG HandleCount,
	 LPFILETIME StartTime,
	 LPFILETIME EndTime);
*/
func ProcessTrace(handleArray *uint64,
	handleCount uint32,
	startTime *FileTime,
	endTime *FileTime) error {
	r1, _, _ := processTrace.Call(
		uintptr(unsafe.Pointer(handleArray)),
		uintptr(handleCount),
		uintptr(unsafe.Pointer(startTime)),
		uintptr(unsafe.Pointer(endTime)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

/*
OpenTraceW API wrapper generated from prototype
EXTERN_C TRACEHANDLE WMIAPI OpenTraceW (
	 PEVENT_TRACE_LOGFILEW Logfile);
*/
func OpenTrace(logfile *EventTraceLogfile) (uint64, error) {
	r1, _, err := openTraceW.Call(
		uintptr(unsafe.Pointer(logfile)))
	if err.(syscall.Errno) == 0 {
		return uint64(r1), nil
	}
	return uint64(r1), err
}

/*
ControlTraceW API wrapper generated from prototype
EXTERN_C ULONG WMIAPI ControlTraceW (
	 TRACEHANDLE TraceHandle,
	 LPCWSTR InstanceName,
	 PEVENT_TRACE_PROPERTIES Properties,
	 ULONG ControlCode);
*/
func ControlTrace(traceHandle uintptr,
	instanceName *uint16,
	properties *EventTraceProperties,
	controlCode uint32) (uint32, error) {
	r1, _, err := controlTraceW.Call(
		uintptr(traceHandle),
		uintptr(unsafe.Pointer(instanceName)),
		uintptr(unsafe.Pointer(properties)),
		uintptr(controlCode))
	if err.(syscall.Errno) == 0 {
		return uint32(r1), nil
	}
	return uint32(r1), err
}

/*
CloseTrace API wrapper generated from prototype
EXTERN_C ULONG WMIAPI CloseTrace (
	 TRACEHANDLE TraceHandle);
*/
func CloseTrace(traceHandle uint64) (uint32, error) {
	r1, _, err := closeTrace.Call(
		uintptr(traceHandle))
	if err.(syscall.Errno) == 0 {
		return uint32(r1), nil
	}
	return uint32(r1), err
}

/*
OpenSCManagerW API wrapper generated from prototype
WINADVAPI SC_HANDLE WINAPI OpenSCManagerW(
	 LPCWSTR lpMachineName,
	LPCWSTR lpDatabaseName,
	DWORD dwDesiredAccess);
*/
func OpenSCManagerW(lpMachineName *uint16,
	lpDatabaseName *uint16,
	dwDesiredAccess uint32) (syscall.Handle, error) {
	r1, _, err := openSCManagerW.Call(
		uintptr(unsafe.Pointer(lpMachineName)),
		uintptr(unsafe.Pointer(lpDatabaseName)),
		uintptr(dwDesiredAccess))
	if err.(syscall.Errno) == 0 {
		return syscall.Handle(r1), nil
	}
	return syscall.Handle(r1), err
}

/*
EnumServicesStatusExW API wrapper generated from prototype
WINADVAPI WINBOOL WINAPI EnumServicesStatusExW(
	 SC_HANDLE hSCManager,
	SC_ENUM_TYPE InfoLevel,
	DWORD dwServiceType,
	DWORD dwServiceState,
	LPBYTE lpServices,
	DWORD cbBufSize,
	LPDWORD pcbBytesNeeded,
	LPDWORD lpServicesReturned,
	LPDWORD lpResumeHandle,
	LPCWSTR pszGroupName);
*/
func EnumServicesStatusEx(hSCManager syscall.Handle,
	infoLevel ScEnumType,
	dwServiceType uint32,
	dwServiceState uint32,
	lpServices *byte,
	cbBufSize uint32,
	pcbBytesNeeded *uint32,
	lpServicesReturned *uint32,
	lpResumeHandle *uint32,
	pszGroupName *uint16) error {
	r1, _, err := enumServicesStatusExW.Call(
		uintptr(hSCManager),
		uintptr(infoLevel),
		uintptr(dwServiceType),
		uintptr(dwServiceState),
		uintptr(unsafe.Pointer(lpServices)),
		uintptr(cbBufSize),
		uintptr(unsafe.Pointer(pcbBytesNeeded)),
		uintptr(unsafe.Pointer(lpServicesReturned)),
		uintptr(unsafe.Pointer(lpResumeHandle)),
		uintptr(unsafe.Pointer(pszGroupName)))
	if r1 == 0 {
		return err
	}
	return nil
}

/*
CloseServiceHandle API wrapper generated from prototype
WINADVAPI WINBOOL WINAPI CloseServiceHandle(
	 SC_HANDLE hSCObject);
*/
func CloseServiceHandle(hSCObject syscall.Handle) error {
	r1, _, err := closeServiceHandle.Call(
		uintptr(hSCObject))
	if r1 == 0 {
		return err
	}
	return nil
}

/////////////////////////////////////////////////////////////////////

/*
RegOpenKeyExW API wrapper generated from prototype
WINADVAPI LONG WINAPI RegOpenKeyExW(
	 HKEY hKey,
	LPCWSTR lpSubKey,
	DWORD ulOptions,
	REGSAM samDesired,
	PHKEY phkResult);
*/
func RegOpenKeyEx(hKey syscall.Handle,
	lpSubKey *uint16,
	ulOptions uint32,
	samDesired uint32,
	phkResult *syscall.Handle) error {
	r1, _, _ := regOpenKeyExW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(lpSubKey)),
		uintptr(ulOptions),
		uintptr(samDesired),
		uintptr(unsafe.Pointer(phkResult)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

/*
RegQueryValueExW API wrapper generated from prototype
WINADVAPI LONG WINAPI RegQueryValueExW(
	 HKEY hKey,
	LPCWSTR lpValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE lpData,
	LPDWORD lpcbData);
*/
func RegQueryValueEx(hKey syscall.Handle,
	lpValueName *uint16,
	lpReserved *uint32,
	lpType *uint32,
	lpData *byte,
	lpcbData *uint32) error {
	r1, _, _ := regQueryValueExW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(lpValueName)),
		uintptr(unsafe.Pointer(lpReserved)),
		uintptr(unsafe.Pointer(lpType)),
		uintptr(unsafe.Pointer(lpData)),
		uintptr(unsafe.Pointer(lpcbData)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

/*
RegCloseKey API wrapper generated from prototype
WINADVAPI LONG WINAPI RegCloseKey(
	 HKEY hKey);
*/
func RegCloseKey(hKey syscall.Handle) error {
	r1, _, _ := regCloseKey.Call(
		uintptr(hKey))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}
