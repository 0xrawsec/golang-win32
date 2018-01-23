package win32

import (
	"syscall"
	"unsafe"
)

// UTF16BytesToString transforms a bytes array of UTF16 encoded characters to
// a Go string
func UTF16BytesToString(utf16 []byte) string {
	return syscall.UTF16ToString(*(*[]uint16)(unsafe.Pointer(&utf16)))
}
