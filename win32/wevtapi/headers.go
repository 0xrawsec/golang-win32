package wevtapi

import (
	"fmt"

	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-win32/win32"
)

// Should be an enum  _EVT_SUBSCRIBE_NOTIFY_ACTION
type EVT_SUBSCRIBE_NOTIFY_ACTION int

const (
	// EVT_SUBSCRIBE_NOTIFY_ACTION enum: https://msdn.microsoft.com/en-us/library/windows/desktop/aa385596(v=vs.85).aspx
	//typedef enum _EVT_SUBSCRIBE_NOTIFY_ACTION {
	EvtSubscribeActionError   = 0
	EvtSubscribeActionDeliver = 1
	//} EVT_SUBSCRIBE_NOTIFY_ACTION;

	// EVT_RENDER_FLAGS enum: https://msdn.microsoft.com/en-us/library/windows/desktop/aa385563(v=vs.85).aspx
	//typedef enum _EVT_RENDER_FLAGS {
	EvtRenderEventValues = 0
	EvtRenderEventXml    = 1
	EvtRenderBookmark    = 2
	//} EVT_RENDER_FLAGS;

	// EVT_SUBSCRIBE_FLAGS enum: https://msdn.microsoft.com/en-us/library/windows/desktop/aa385588(v=vs.85).aspx
	//typedef enum _EVT_SUBSCRIBE_FLAGS {
	EvtSubscribeToFutureEvents      = 1
	EvtSubscribeStartAtOldestRecord = 2
	EvtSubscribeStartAfterBookmark  = 3
	EvtSubscribeOriginMask          = 0x3
	EvtSubscribeTolerateQueryErrors = 0x1000
	EvtSubscribeStrict              = 0x10000
	//} EVT_SUBSCRIBE_FLAGS;
)

type EVT_SUBSCRIBE_CALLBACK func(Action EVT_SUBSCRIBE_NOTIFY_ACTION, UserContext win32.PVOID, Event EVT_HANDLE) uintptr
type EVT_HANDLE win32.HANDLE

func TestCallback(Action EVT_SUBSCRIBE_NOTIFY_ACTION, UserContext win32.PVOID, Event EVT_HANDLE) uintptr {
	log.Info("In TestCallback")
	fmt.Printf("Super it works\n")
	return uintptr(0)
}
