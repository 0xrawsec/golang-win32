package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"testing"
	"time"
	"win32"
	"win32/kernel32"
	"win32/wevtapi"

	"github.com/0xrawsec/golang-utils/log"
)

const (
	SysmonChannel   = "Microsoft-Windows-Sysmon/Operational"
	SecurityChannel = "Security"
)

func init() {
	log.InitLogger(log.LDebug)
}

func TestPushSubscribe(t *testing.T) {
	_, err := wevtapi.EvtSubscribe(
		wevtapi.EVT_HANDLE(win32.NULL),
		win32.HANDLE(win32.NULL),
		//"Microsoft-Windows-Sysmon/Operational",
		"Microsoft-Windows-Sysmon/Operational",
		"*",
		wevtapi.EVT_HANDLE(win32.NULL),
		win32.PVOID(win32.NULL),
		wevtapi.TestCallback,
		win32.DWORD(2))
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	//time.Sleep(15 * time.Second)
}

func TestPullSubscribe(t *testing.T) {
	event, err := kernel32.CreateEvent(0, win32.TRUE, win32.TRUE, "")
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	/* hSubscription = EvtSubscribe(NULL,
	aWaitHandles[1], pwsPath, pwsQuery, NULL, NULL, NULL, EvtSubscribeStartAtOldestRecord); */
	sub, err := wevtapi.EvtPullSubscribe(
		wevtapi.EVT_HANDLE(win32.NULL),
		event,
		"Microsoft-Windows-Sysmon/Operational",
		"*",
		wevtapi.EVT_HANDLE(win32.NULL),
		win32.PVOID(win32.NULL),
		win32.DWORD(1))

	if err != nil {
		t.Log(err)
		t.Fail()
	}
	rc := kernel32.WaitForSingleObject(event, win32.INFINITE)
	t.Log(fmt.Sprintf("0x%08x", rc))
	log.Info("Got Signal")

	//for i := 0; i < 3; i++ {
	for {
		events, err := wevtapi.EvtNext(sub, win32.INFINITE)
		if err != nil {
			t.Log(err)
			t.Fail()
		}
		log.Infof("Got %d events", len(events))
		for _, event := range events {
			data, err := wevtapi.EvtRenderXML(event)
			if err != nil {
				t.Log(err)
			}
			dataUTF8 := win32.UTF16BytesToString(data)
			log.Info(string(dataUTF8))
			e := wevtapi.XMLEvent{}
			err = xml.Unmarshal([]byte(dataUTF8), &e)
			if err != nil {
				log.Error(err)
			}
			bytes, err := json.Marshal(&e)
			if err != nil {
				log.Error(err)
			}
			log.Info(string(bytes))
			wevtapi.EvtClose(event)
		}
	}

	err = kernel32.ResetEvent(event)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
}

func TestGetAllEventsFromChannel(t *testing.T) {
	signal := make(chan bool)
	count := 0
	go func() {
		time.Sleep(10 * time.Second)
		signal <- false
	}()
	//c := wevtapi.GetAllEventsFromChannel(SysmonChannel, wevtapi.EvtSubscribeToFutureEvents, signal)
	c := wevtapi.GetAllEventsFromChannel(SecurityChannel, wevtapi.EvtSubscribeToFutureEvents, signal)
	//c := wevtapi.GetAllEventsFromChannel(SecurityChannel, wevtapi.EvtSubscribeStartAtOldestRecord, signal)
	for e := range c {
		bytes, err := json.Marshal(e)
		if err != nil {
			log.Error(err)
		}
		log.Info(string(bytes))
		count++
	}
	t.Logf("Event Count: %d", count)
}
