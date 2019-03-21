package wevtapi

import (
	"syscall"
	"unsafe"

	"github.com/0xrawsec/golang-win32/win32"
)

// EvtClose wrapper
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa385344(v=vs.85).aspx
func EvtClose(Object EVT_HANDLE) error {
	r1, _, lastErr := evtClose.Call(uintptr(Object))
	if win32.BOOL(r1) == win32.FALSE {
		return lastErr
	}
	return nil
}

func EvtSubscribe(
	Session EVT_HANDLE,
	SignalEvent win32.HANDLE,
	ChannelPath string,
	Query string,
	Bookmark EVT_HANDLE,
	context win32.PVOID,
	Callback EVT_SUBSCRIBE_CALLBACK,
	Flags win32.DWORD) (EVT_HANDLE, error) {
	channelPath, err := syscall.UTF16PtrFromString(ChannelPath)
	if err != nil {
		return EVT_HANDLE(0), err
	}
	query, err := syscall.UTF16PtrFromString(Query)
	if err != nil {
		return EVT_HANDLE(0), err
	}
	r1, _, lastErr := evtSubscribe.Call(
		uintptr(Session),
		uintptr(SignalEvent),
		uintptr(unsafe.Pointer(channelPath)),
		uintptr(unsafe.Pointer(query)),
		uintptr(Bookmark),
		uintptr(context),
		syscall.NewCallback(Callback),
		uintptr(Flags))
	if r1 == win32.NULL {
		return EVT_HANDLE(r1), lastErr
	}
	return EVT_HANDLE(r1), nil
}

func EvtPullSubscribe(
	Session EVT_HANDLE,
	SignalEvent win32.HANDLE,
	ChannelPath string,
	Query string,
	Bookmark EVT_HANDLE,
	context win32.PVOID,
	Flags win32.DWORD) (EVT_HANDLE, error) {
	channelPath, err := syscall.UTF16PtrFromString(ChannelPath)
	if err != nil {
		return EVT_HANDLE(0), err
	}
	query, err := syscall.UTF16PtrFromString(Query)
	if err != nil {
		return EVT_HANDLE(0), err
	}
	r1, _, lastErr := evtSubscribe.Call(
		uintptr(Session),
		uintptr(SignalEvent),
		uintptr(unsafe.Pointer(channelPath)),
		uintptr(unsafe.Pointer(query)),
		uintptr(Bookmark),
		uintptr(context),
		win32.NULL,
		uintptr(Flags))
	if r1 == win32.NULL {
		return EVT_HANDLE(r1), lastErr
	}
	return EVT_HANDLE(r1), nil
}

func EvtNext(ResultSet EVT_HANDLE, Timeout win32.DWORD) ([]EVT_HANDLE, error) {
	/*
		BOOL WINAPI EvtNext(
		  _In_  EVT_HANDLE  ResultSet,
		  _In_  DWORD       EventArraySize,
		  _In_  EVT_HANDLE* EventArray,
		  _In_  DWORD       Timeout,
		  _In_  DWORD       Flags, // Must be NULL
		  _Out_ PDWORD      Returned
		);
	*/
	// ArraySize could not be too big 4096 (not more than 600 ???)
	// Weird handles at the end of array if we put higher than 64
	const EventArraySize = 10
	var EventArray [EventArraySize]EVT_HANDLE
	var Returned win32.DWORD

	// log.Debugf("ResultSet = 0x%08x", uintptr(ResultSet))
	// log.Debugf("EventArraySize = %d", EventArraySize)
	// log.Debugf("Timeout = 0x%08x", Timeout)
	r1, _, lastErr := evtNext.Call(
		uintptr(ResultSet),
		uintptr(win32.DWORD(EventArraySize)),
		uintptr(unsafe.Pointer(&EventArray)),
		uintptr(Timeout),
		uintptr(0),
		uintptr(unsafe.Pointer(&Returned)))
	// log.Debugf("Returned = %d", Returned)
	// log.Debugf("EventArray = %v", EventArray)

	if win32.BOOL(r1) == win32.FALSE {
		return EventArray[:Returned], lastErr
	}
	return EventArray[:Returned], nil
}

func EvtRenderXML(Context EVT_HANDLE) ([]byte, error) {
	// 65536 buffsize
	const buffSize = 0x1 << 16
	var buffer [buffSize]byte
	var BufferUsed win32.DWORD
	var PropertyCount win32.DWORD

	r1, _, lastErr := evtRender.Call(
		uintptr(0),
		uintptr(Context),
		uintptr(EvtRenderEventXml),
		uintptr(buffSize),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&BufferUsed)),
		uintptr(unsafe.Pointer(&PropertyCount)))
	// log.Debugf("BufferUsed = %d", BufferUsed)
	if win32.BOOL(r1) == win32.FALSE {
		return buffer[:], lastErr
	}
	return buffer[:BufferUsed], nil
}
