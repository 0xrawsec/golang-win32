package win32

import (
	"syscall"
	"testing"
)

func TestUTF16PtrToString(t *testing.T) {
	ts := "This is just a test string"
	tsUtf16Ptr := syscall.StringToUTF16Ptr(ts)

	if UTF16PtrToString(tsUtf16Ptr) != ts {
		t.Fail()
	}
	t.Logf("UTF16 Ptr converted back: %s", UTF16PtrToString(tsUtf16Ptr))

}
