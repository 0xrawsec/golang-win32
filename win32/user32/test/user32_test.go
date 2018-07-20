package main

import (
	"testing"
	"win32/user32"
)

func TestMessageBox(t *testing.T) {

	if rc, err := user32.MessageBox(0, "Message box popped\nfrom Golang", "Go user32.dll wrapper", 0); err != nil {
		t.Logf("rc:%d error:%s", rc, err)
		t.FailNow()
	}
}
