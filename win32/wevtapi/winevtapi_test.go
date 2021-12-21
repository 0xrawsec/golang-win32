// +build windows

package wevtapi

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
)

const (
	SysmonChannel   = "Microsoft-Windows-Sysmon/Operational"
	SecurityChannel = "Security"
	XMLFile         = "applocker.xml.2"
	nCalls          = 1000
)

func init() {
	//log.InitLogger(log.LDebug)
}

func callWhoami(count int) {
	for i := 0; i < count; i++ {
		exec.Command("whoami.exe").Start()
	}
}

type CallbackContext struct {
	t                 *testing.T
	Counter           uint64
	xmlRenderedEvents chan string
}

func (c *CallbackContext) String() string {

	return fmt.Sprintf("Counter: %d", c.Counter)
}

func CallbackTest(Action EVT_SUBSCRIBE_NOTIFY_ACTION, UserContext win32.PVOID, Event EVT_HANDLE) uintptr {
	ctx := (*CallbackContext)(unsafe.Pointer(UserContext))
	switch Action {
	case EvtSubscribeActionDeliver:
		data, err := EvtRenderXML(Event)
		if err != nil {
			ctx.t.Errorf("Error converting event to XML: %s", err)
		}
		dataUTF8 := win32.UTF16BytesToString(data)
		ctx.xmlRenderedEvents <- dataUTF8
		ctx.t.Log(dataUTF8)
		ctx.Counter++
	case EvtSubscribeActionError:
		ctx.t.Errorf("Error")
	}
	return uintptr(0)
}

func TestPushSubscribe(t *testing.T) {
	ctx := &CallbackContext{t, 0, make(chan string)}
	sub, err := EvtSubscribe(
		EVT_HANDLE(win32.NULL),

		win32.HANDLE(win32.NULL),
		"Microsoft-Windows-Sysmon/Operational",
		"*",
		EVT_HANDLE(win32.NULL),
		win32.PVOID(unsafe.Pointer(ctx)),
		CallbackTest,
		EvtSubscribeToFutureEvents)
	if err != nil {
		t.Log(err)
		t.Fail()
	}

	go func() {
		for range ctx.xmlRenderedEvents {
		}
	}()

	time.Sleep(15 * time.Second)
	EvtClose(sub)
	t.Log(ctx)
}

func TestUnmarshalXML(t *testing.T) {
	f, err := os.Open(XMLFile)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	dec := xml.NewDecoder(f)
	for {
		xe := XMLEvent{}

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
	sub, err := EvtPullSubscribe(
		EVT_HANDLE(win32.NULL),
		event,
		"Microsoft-Windows-Sysmon/Operational",
		"*",
		EVT_HANDLE(win32.NULL),
		win32.PVOID(win32.NULL),
		EvtSubscribeToFutureEvents)

	if err != nil {
		t.Log(err)
		t.Fail()
	}
	rc := kernel32.WaitForSingleObject(event, win32.INFINITE)
	t.Log(fmt.Sprintf("0x%08x", rc))
	log.Info("Got Signal")

	//for i := 0; i < 3; i++ {
	for {
		events, err := EvtNext(sub, win32.INFINITE)
		if err != nil {
			t.Log(err)
			t.Fail()
		}
		log.Infof("Got %d events", len(events))
		for _, event := range events {
			data, err := EvtRenderXML(event)
			if err != nil {
				t.Log(err)
			}
			dataUTF8 := win32.UTF16BytesToString(data)
			log.Info(string(dataUTF8))
			e := XMLEvent{}
			err = xml.Unmarshal([]byte(dataUTF8), &e)
			if err != nil {
				log.Error(err)
			}
			bytes, err := json.Marshal(&e)
			if err != nil {
				log.Error(err)
			}
			log.Info(string(bytes))
			EvtClose(event)
		}
	}

	err = kernel32.ResetEvent(event)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
}
func TestPullProviderPassive(t *testing.T) {
	countEvents := 0
	wg := sync.WaitGroup{}
	ep := NewPullEventProvider()
	d := 60 * time.Second

	wg.Add(1)
	go func() {
		for e := range ep.FetchEvents([]string{SysmonChannel, SecurityChannel},
			EvtSubscribeToFutureEvents) {
			// Do conversion to json
			e.ToJSONEvent()
			countEvents++
		}
		wg.Done()
	}()

	time.Sleep(d)
	ep.Stop()
	t.Logf("Received %.2f EPS", float64(countEvents)/d.Seconds())
}

func TestPullProviderFetchEvents(t *testing.T) {
	//signal := make(chan bool)
	sysmonCounter := make(map[string]int)
	securityCounter := make(map[string]int)
	countEvents := 0
	wg := sync.WaitGroup{}

	ep := NewPullEventProvider()

	wg.Add(1)
	go func() {
		for e := range ep.FetchEvents([]string{SysmonChannel, SecurityChannel},
			EvtSubscribeToFutureEvents) {
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

	log.Infof("Calling x%d whoami.exe", nCalls)
	callWhoami(nCalls)
	log.Infof("Sleeping")
	time.Sleep(5 * time.Second)
	// Stopping EventProvider
	ep.Stop()
	wg.Wait()

	for image, count := range sysmonCounter {
		if strings.HasSuffix(image, ".test.exe") {
			continue
		}
		secCount, ok := securityCounter[image]
		if ok {
			t.Logf("%s: %d", image, count)
		} else {
			t.Errorf("Image: %s Sysmon: %d Security: %d", image, count, secCount)
		}
	}
	t.Logf("Total Events Retrieved: %d", countEvents)
}

func TestPushProviderPassive(t *testing.T) {
	countEvents := 0
	wg := sync.WaitGroup{}
	ep := NewPushEventProvider()
	d := 60 * time.Second

	wg.Add(1)
	go func() {
		for e := range ep.FetchEvents([]string{SysmonChannel, SecurityChannel},
			EvtSubscribeToFutureEvents) {
			// Do conversion to json
			e.ToJSONEvent()
			countEvents++
		}
		wg.Done()
	}()

	time.Sleep(d)
	ep.Stop()
	t.Logf("Received %.2f EPS", float64(countEvents)/d.Seconds())
}

func TestPushProviderFetchEvents(t *testing.T) {
	//signal := make(chan bool)
	sysmonCounter := make(map[string]int)
	securityCounter := make(map[string]int)
	countEvents := 0
	wg := sync.WaitGroup{}

	ep := NewPushEventProvider()
	if err := exec.Command("auditpol", "/set", `/subcategory:Process Creation`, "/success:enable", "/failure:enable").Run(); err != nil {
		t.Error("Failed to set audit policy")
		t.FailNow()
	}

	wg.Add(1)
	go func() {
		for e := range ep.FetchEvents([]string{SysmonChannel, SecurityChannel},
			EvtSubscribeToFutureEvents) {
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

	log.Infof("Calling x%d whoami.exe", nCalls)
	callWhoami(nCalls)
	log.Infof("Sleeping")
	time.Sleep(5 * time.Second)
	// Stopping EventProvider
	log.Infof("Stopping event provider")
	ep.Stop()
	wg.Wait()

	for image, count := range sysmonCounter {
		if strings.HasSuffix(image, ".test.exe") {
			continue
		}
		secCount, ok := securityCounter[image]
		if ok {
			t.Logf("%s: %d", image, count)
		} else {
			t.Errorf("Image: %s Sysmon: %d Security: %d", image, count, secCount)
		}
	}
	t.Logf("Total Events Retrieved: %d", countEvents)
}
