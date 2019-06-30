package win32

import (
	"crypto/rand"
	"fmt"
	"syscall"
	"unsafe"
)

// UTF16BytesToString transforms a bytes array of UTF16 encoded characters to
// a Go string
func UTF16BytesToString(utf16 []byte) string {
	return syscall.UTF16ToString(*(*[]uint16)(unsafe.Pointer(&utf16)))
}

// UTF16PtrToString transforms a *uint16 to a Go string
func UTF16PtrToString(utf16 *uint16) string {
	return syscall.UTF16ToString(*(*[]uint16)(unsafe.Pointer(&utf16)))
}

// UUID is a simple UUID generator
func UUID() (uuid string, err error) {
	b := make([]byte, 16)
	_, err = rand.Read(b)
	if err != nil {
		return
	}
	uuid = fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	return
}
