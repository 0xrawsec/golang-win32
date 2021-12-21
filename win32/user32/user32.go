// +build windows

package user32

import (
	"syscall"
	"unsafe"

	"github.com/0xrawsec/golang-win32/win32"
)

func MessageBox(hWnd win32.HWND, text, caption string, uType win32.UINT) (int, error) {
	lpText := syscall.StringToUTF16Ptr(text)
	lpCaption := syscall.StringToUTF16Ptr(caption)
	rc, _, err := messageBoxW.Call(
		uintptr(hWnd),
		uintptr(unsafe.Pointer(lpText)),
		uintptr(unsafe.Pointer(lpCaption)),
		uintptr(uType))
	if rc == 0 {
		return int(rc), err
	}
	return int(rc), nil
}
