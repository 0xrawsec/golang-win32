//go:build windows
// +build windows

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

func UTF16AtOffsetToString(pstruct uintptr, offset uintptr) string {
	out := make([]uint16, 0, 64)
	wc := (*uint16)(unsafe.Pointer(pstruct + offset))
	for i := uintptr(2); *wc != 0; i += 2 {
		out = append(out, *wc)
		wc = (*uint16)(unsafe.Pointer(pstruct + offset + i))
	}
	return syscall.UTF16ToString(out)
}

func CopyData(pointer uintptr, size int) []byte {
	out := make([]byte, size)
	for it := pointer; it != pointer+uintptr(size); it++ {
		b := (*byte)(unsafe.Pointer(it))
		out = append(out, *b)
	}
	return out
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

// Add helper for pointer arithmetic
func Add(p unsafe.Pointer, i uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(p) + i)
}

func Lower(p, other unsafe.Pointer) bool {
	return uintptr(p) < uintptr(other)
}
