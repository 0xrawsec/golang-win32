package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
	"github.com/0xrawsec/golang-win32/win32/wevtapi"
)

const (
	SysmonChannel   = "Microsoft-Windows-Sysmon/Operational"
	SecurityChannel = "Security"
	XMLFile         = "applocker.xml.2"
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

func TestUnmarshalXML(t *testing.T) {
	f, err := os.Open(XMLFile)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	dec := xml.NewDecoder(f)
	for {
		xe := wevtapi.XMLEvent{}

		if err := dec.Decode(&xe); err != nil {
			t.Log(err)
			break
		}
		//t.Logf("UserData: %v", xe.UserData)
		//t.Logf("EventData: %v", xe.EventData)

		b, err := json.Marshal(xe.ToMap())
		if err != nil {
			t.Log(err)
			t.FailNow()
		}
		t.Log(string(b))
	}
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

/*func TestGetAllEventsFromChannel(t *testing.T) {
	signal := make(chan bool)
	count := 0
	go func() {
		time.Sleep(10 * time.Second)
		signal <- false
	}()
	c := wevtapi.GetAllEventsFromChannel(SysmonChannel, wevtapi.EvtSubscribeToFutureEvents, signal)
	for e := range c {
		bytes, err := json.Marshal(e.ToJSONEvent())
		if err != nil {
			log.Error(err)
		}
		log.Info(string(bytes))
		count++
	}
	t.Logf("Event Count: %d", count)
}*/

func TestGetAllEventsFromChannels(t *testing.T) {
	//signal := make(chan bool)
	sysmonCounter := make(map[string]int)
	securityCounter := make(map[string]int)
	countEvents := 0
	wg := sync.WaitGroup{}

	ep := wevtapi.NewEventProvider()

	wg.Add(1)
	go func() {
		for e := range ep.FetchEvents([]string{SysmonChannel, SecurityChannel},
			wevtapi.EvtSubscribeToFutureEvents) {
			j := e.ToJSONEvent()
			channel := j.Event.System.Channel
			switch channel {
			case SecurityChannel:
				if j.Event.System.EventID == "4688" {
					image := j.Event.EventData["NewProcessName"]
					securityCounter[image]++
				}
			case SysmonChannel:
				if j.Event.System.EventID == "1" {
					image := j.Event.EventData["Image"]
					sysmonCounter[image]++
				}
			}
			countEvents++
		}
		wg.Done()
	}()

	for i := 0; i < 1000; i++ {
		exec.Command("whoami.exe").Run()
	}
	time.Sleep(5 * time.Second)
	// Stopping EventProvider
	ep.Stop()
	wg.Wait()

	for image, count := range sysmonCounter {
		secCount, ok := securityCounter[image]
		if ok {
			t.Logf("%s: %d", image, count)
		} else {
			t.Errorf("Image: %s Sysmon: %d Security: %d", image, count, secCount)
		}
	}
	t.Logf("Total Events Retrieved: %d", countEvents)
}
