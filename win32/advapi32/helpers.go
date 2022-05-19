//go:build windows
// +build windows

package advapi32

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/0xrawsec/golang-win32/win32"
)

// ServiceWin32NamesByPid is an helper function to return the service
// name of a SERVICE_WIN32 from a pid
func ServiceWin32NamesByPid(pid uint32) (string, error) {
	se, err := NewServiceEnumerator()
	if err != nil {
		return "", err
	}
	defer se.Close()
	return se.ServiceNamesByPID(pid, win32.SERVICE_WIN32)
}

// ServiceEnumerator structure used to enumerate windows services
type ServiceEnumerator struct {
	hMan syscall.Handle
}

// NewServiceEnumerator initializes a new ServiceEnumerator structure
func NewServiceEnumerator() (*ServiceEnumerator, error) {
	hman, err := OpenSCManagerW(nil, nil, SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, fmt.Errorf("Failed to open service manager: %s", err)
	}
	return &ServiceEnumerator{hman}, nil
}

// Services retrieves the list of services of a certain type
// for service types look at https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/nf-winsvc-enumservicesstatusexw
// service types are available in win32 package Ex: win32.SERVICE_WIN32
func (s *ServiceEnumerator) Services(stype uint32) (ss []EnumServiceStatusProcess, err error) {
	ss = make([]EnumServiceStatusProcess, 0)
	bytesNeeded := uint32(0)
	servicesReturned := uint32(0)
	resumeHandle := uint32(0)
	cbBufSize := uint32(0)

	if err = EnumServicesStatusEx(s.hMan,
		SC_ENUM_PROCESS_INFO,
		stype,
		SERVICE_ACTIVE,
		nil,
		cbBufSize,
		&bytesNeeded,
		&servicesReturned,
		&resumeHandle,
		nil); err.(syscall.Errno) != win32.ERROR_MORE_DATA {
		return
	}
	ss = make([]EnumServiceStatusProcess, int(bytesNeeded/uint32(unsafe.Sizeof(EnumServiceStatusProcess{})))+1)
	cbBufSize = uint32(uintptr(len(ss)) * unsafe.Sizeof(EnumServiceStatusProcess{}))

	// Reset handle
	resumeHandle = uint32(0)

	if err = EnumServicesStatusEx(s.hMan,
		SC_ENUM_PROCESS_INFO,
		stype,
		SERVICE_ACTIVE,
		(*byte)(unsafe.Pointer(&ss[0])),
		cbBufSize,
		&bytesNeeded,
		&servicesReturned,
		&resumeHandle,
		nil); err != nil {
		return
	}
	return ss[:servicesReturned], err
}

// ServiceNamesByPID returns a comma separated list of the service names
// a process (svchost in particular) can be associated with several services
func (s *ServiceEnumerator) ServiceNamesByPID(pid uint32, stype uint32) (string, error) {
	out := make([]string, 0)
	services, err := s.Services(stype)
	if err != nil {
		return "", err
	}
	for _, service := range services {
		if service.ServiceStatusProcess.ProcessId == pid {
			sn := win32.UTF16PtrToString(service.ServiceName)
			out = append(out, sn)
		}
	}

	// pid is not a service
	if len(out) == 0 {
		return "N/A", nil
	}
	return strings.Join(out, ","), nil
}

// Close gently closes the ServiceEnumerator
func (s *ServiceEnumerator) Close() error {
	return CloseServiceHandle(s.hMan)
}

///////////////////////////////////////////////////////////////

// regOpenKeyRecFromPath opens registry keys recursively
func regOpenKeyRecFromPath(hKey syscall.Handle, path []string, samDesired uint32) (hSubKey syscall.Handle, err error) {
	defer RegCloseKey(hKey)
	subkey := path[0]
	err = RegOpenKeyEx(
		hKey,
		syscall.StringToUTF16Ptr(subkey),
		0,
		samDesired,
		&hSubKey)
	if err != nil || len(path) == 1 {
		return
	}
	return regOpenKeyRecFromPath(hSubKey, path[1:], samDesired)
}

// RegOpenKeyRecFromString returns a handle to the registry key pointed by a full path
// it opens keys recursively Ex: HKLM\\SYSTEM\\CurrentControlSet\\Control\\EarlyStartServices
func RegOpenKeyRecFromString(path string, samDesired uint32) (hSubKey syscall.Handle, err error) {
	var hKey syscall.Handle
	sp := strings.Split(path, string(os.PathSeparator))
	root, key := sp[0], sp[1:]
	switch root {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		hKey = HKEY_LOCAL_MACHINE
	case "HKU", "HKEY_USERS":
		hKey = HKEY_USERS
	case "HKCR", "HKEY_CLASSES_ROOT":
		hKey = HKEY_CLASSES_ROOT
	case "HKCU", "HKEY_CURRENT_USER":
		hKey = HKEY_CURRENT_USER
	case "HKEY_CURRENT_CONFIG":
		hKey = HKEY_CURRENT_CONFIG
	default:
		err = fmt.Errorf("Unknown root key %s", root)
		return
	}
	return regOpenKeyRecFromPath(hKey, key, samDesired)
}

// RegGetValueSizeFromString returns the size of a registry value in bytes
func RegGetValueSizeFromString(reg string) (size uint32, err error) {
	var hKey syscall.Handle

	sp := strings.Split(reg, string(os.PathSeparator))
	value := sp[len(sp)-1]

	if hKey, err = RegOpenKeyRecFromString(filepath.Join(sp[0:len(sp)-1]...), win32.KEY_READ); err != nil {
		return
	}
	defer RegCloseKey(hKey)
	if err = RegQueryValueEx(
		hKey,
		syscall.StringToUTF16Ptr(value),
		nil,
		nil,
		nil,
		&size); err != nil {
		return
	}
	return
}

var (
	ErrUnkownRegValueType = errors.New("unknown registry value type")
)

// ParseRegValue is a helper function to parse data stored in registry
func ParseRegValue(data []byte, dtype uint32) (interface{}, error) {
	switch dtype {
	case syscall.REG_BINARY:
		return data, nil
	case syscall.REG_DWORD:
		return binary.LittleEndian.Uint32(data), nil
	case syscall.REG_DWORD_BIG_ENDIAN:
		return binary.BigEndian.Uint32(data), nil
	case syscall.REG_MULTI_SZ:
		out := make([]string, 0)
		buf := make([]uint16, 0)
		if len(data) > 0 {
			p := unsafe.Pointer(&data[0])
			for i := uintptr(2); i < uintptr(len(data)); i += 2 {
				wc := (*uint16)(p)
				if *wc == 0 {
					out = append(out, syscall.UTF16ToString(buf))
					buf = make([]uint16, 0)
				} else {
					buf = append(buf, *wc)
				}
				p = win32.Add(p, 2)
			}
			if len(buf) > 0 {
				out = append(out, syscall.UTF16ToString(buf))
			}
		}
		return out, nil
	case syscall.REG_NONE:
		return nil, nil
	case syscall.REG_QWORD:
		return binary.LittleEndian.Uint64(data), nil
	case syscall.REG_SZ, syscall.REG_EXPAND_SZ, syscall.REG_LINK:
		return win32.UTF16BytesToString(data), nil
	default:
		return nil, fmt.Errorf("%w 0x%08x", ErrUnkownRegValueType, dtype)
	}
}

// RegGetValueFromString returns the data associated to a registry value as well as
// its type represented by a uint32
func RegGetValueFromString(path string) (data []byte, dtype uint32, err error) {
	var hKey syscall.Handle
	var lpcbData uint32

	sp := strings.Split(path, string(os.PathSeparator))
	value := sp[len(sp)-1]

	if hKey, err = RegOpenKeyRecFromString(filepath.Join(sp[0:len(sp)-1]...), win32.KEY_READ); err != nil {
		return
	}
	defer RegCloseKey(hKey)

	if err = RegQueryValueEx(
		hKey,
		syscall.StringToUTF16Ptr(value),
		nil,
		&dtype,
		nil,
		&lpcbData); err != nil {
		return
	}

	// there is nothing to query for
	if lpcbData == 0 {
		return
	}

	data = make([]byte, lpcbData)
	if err = RegQueryValueEx(
		hKey,
		syscall.StringToUTF16Ptr(value),
		nil,
		&dtype,
		(*byte)(unsafe.Pointer(&data[0])),
		&lpcbData); err != nil {
		return
	}
	return
}

func RegEnumValues(root string) (values []string, err error) {
	var hKey syscall.Handle

	values = make([]string, 0)
	valueName := [MAX_VALUE_NAME]uint16{}

	if hKey, err = RegOpenKeyRecFromString(root, win32.KEY_READ); err != nil {
		return
	}

	for i := uint32(0); err == nil; i++ {
		valueNameLen := uint32(MAX_KEY_LENGTH)
		err = RegEnumValueW(
			hKey,
			i,
			&valueName[0],
			&valueNameLen,
			nil,
			nil,
			nil,
			nil,
		)

		if err == nil {
			values = append(values, syscall.UTF16ToString(valueName[:]))
		}
	}

	// means we enumerated all keys
	if err == syscall.Errno(win32.ERROR_NO_MORE_ITEMS) {
		err = nil
	}

	return
}

func RegEnumKeys(root string) (keys []string, err error) {
	var hKey syscall.Handle

	keys = make([]string, 0)
	keyName := [MAX_KEY_LENGTH]uint16{}

	if hKey, err = RegOpenKeyRecFromString(root, win32.KEY_READ); err != nil {
		return
	}

	for i := uint32(0); err == nil; i++ {
		keyNameLen := uint32(MAX_KEY_LENGTH)
		err = RegEnumKeyExW(
			hKey,
			i,
			&keyName[0],
			&keyNameLen,
			nil,
			nil,
			nil,
			nil,
		)

		if err == nil {
			keys = append(keys, syscall.UTF16ToString(keyName[:]))
		}
	}

	// means we enumerated all keys
	if err == syscall.Errno(win32.ERROR_NO_MORE_ITEMS) {
		err = nil
	}

	return
}
