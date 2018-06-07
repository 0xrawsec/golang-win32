package wevtapi

import (
	"encoding/xml"
	"fmt"
	"syscall"
	"time"
	"win32"
	"win32/kernel32"

	"github.com/0xrawsec/golang-utils/log"
)

///////////////////////////////// XMLEvent /////////////////////////////////////

type Data struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",innerxml"`
} //`xml:"Data"`

type XMLEvent struct {
	EventData struct {
		Data []Data
	} `xml:"EventData"`
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
			Guid string `xml:"Guid,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Version     string `xml:"Version"`
		Level       string `xml:"Level"`
		Task        string `xml:"Task"`
		Opcode      string `xml:"Opcode"`
		Keywords    string `xml:"Keywords"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID string `xml:"EventRecordID"`
		Correlation   struct {
		} `xml:"Correlation"`
		Execution struct {
			ProcessID string `xml:"ProcessID,attr"`
			ThreadID  string `xml:"ThreadID,attr"`
		} `xml:"Execution"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
		Security struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`
}

func (xe *XMLEvent) ToJSONEvent() *JSONEvent {
	je := NewJSONEvent()
	for _, d := range xe.EventData.Data {
		je.Event.EventData[d.Name] = d.Value
	}
	// System
	je.Event.System.Provider.Name = xe.System.Provider.Name
	je.Event.System.Provider.Guid = xe.System.Provider.Guid
	je.Event.System.EventID = xe.System.EventID
	je.Event.System.Version = xe.System.Version
	je.Event.System.Level = xe.System.Level
	je.Event.System.Task = xe.System.Task
	je.Event.System.Opcode = xe.System.Opcode
	je.Event.System.Keywords = xe.System.Keywords
	je.Event.System.TimeCreated.SystemTime = xe.System.TimeCreated.SystemTime
	je.Event.System.EventRecordID = xe.System.EventRecordID
	je.Event.System.Correlation = xe.System.Correlation
	je.Event.System.Execution.ProcessID = xe.System.Execution.ProcessID
	je.Event.System.Execution.ThreadID = xe.System.Execution.ThreadID
	je.Event.System.Channel = xe.System.Channel
	je.Event.System.Computer = xe.System.Computer
	je.Event.System.Security.UserID = xe.System.Security.UserID
	return &je
}

//////////////////////////////// JSONEvent /////////////////////////////////////

type JSONEvent struct {
	Event struct {
		EventData map[string]string `xml:"EventData"`
		System    struct {
			Provider struct {
				Name string `xml:"Name,attr"`
				Guid string `xml:"Guid,attr"`
			} `xml:"Provider"`
			EventID     string `xml:"EventID"`
			Version     string `xml:"Version"`
			Level       string `xml:"Level"`
			Task        string `xml:"Task"`
			Opcode      string `xml:"Opcode"`
			Keywords    string `xml:"Keywords"`
			TimeCreated struct {
				SystemTime string `xml:"SystemTime,attr"`
			} `xml:"TimeCreated"`
			EventRecordID string `xml:"EventRecordID"`
			Correlation   struct {
			} `xml:"Correlation"`
			Execution struct {
				ProcessID string `xml:"ProcessID,attr"`
				ThreadID  string `xml:"ThreadID,attr"`
			} `xml:"Execution"`
			Channel  string `xml:"Channel"`
			Computer string `xml:"Computer"`
			Security struct {
				UserID string `xml:"UserID,attr"`
			} `xml:"Security"`
		} `xml:"System"`
	}
}

func NewJSONEvent() (je JSONEvent) {
	je.Event.EventData = make(map[string]string)
	return je
}

////////////////////////////////////////////////////////////////////////////////

func GotSignal(signals chan bool) (signal bool, gotsig bool) {
	select {
	case sig := <-signals:
		return sig, true
	default:
	}
	return false, false
}

// GetAllEventsFromChannel returns a Go channel containing XMLEvents retrieved
// from the given Windows Event Channel given in parameter
// flag has to be a value from enum EVT_SUBSCRIBE_FLAGS (c.f. headers.go)
// signal is used to stop the collection process
func GetAllEventsFromChannel(channel string, flag int, signal chan bool) (c chan *XMLEvent) {
	var err error

	// Prep the chan
	c = make(chan *XMLEvent, 42)

	// Creating event
	// If we reuse name, we reuse event, even across processes
	eUUID, err := win32.UUID()
	if err != nil {
		log.LogErrorAndExit(fmt.Errorf("Cannot generate UUID: %s", err))
	}

	log.Debugf("Windows Event UUID (Channel:%s): %s", channel, eUUID)
	event, err := kernel32.CreateEvent(0, win32.TRUE, win32.TRUE, eUUID)
	if err != nil {
		log.Errorf("Cannot create event: %s", err)
		close(c)
		return
	}

	sub, err := EvtPullSubscribe(
		EVT_HANDLE(win32.NULL),
		event,
		channel,
		"*",
		EVT_HANDLE(win32.NULL),
		win32.PVOID(win32.NULL),
		win32.DWORD(flag))

	if err != nil {
		log.Errorf("Failed to subscribe to channel \"%s\": %s", channel, err)
		close(c)
		return
	}

	// Go routine returning the events
	go func() {
		// Closing output channel
		defer close(c)
		// Closing the subscriptions
		defer EvtClose(sub)
		// Closing event
		defer kernel32.CloseHandle(event)

		for {
			rc := kernel32.WaitForSingleObject(event, win32.DWORD(1000))
			log.Debugf("Got signal, events ready (Channel: %s): 0x%08x", channel, rc)
			switch rc {
			case win32.WAIT_TIMEOUT:
				// Check if we received a signal to stop
				if _, got := GotSignal(signal); got {
					return
				}

			case win32.WAIT_OBJECT_0:
				for {
					// Check if we received a signal to stop
					if _, got := GotSignal(signal); got {
						return
					}

					// Try to get events
					events, err := EvtNext(sub, win32.INFINITE)
					if err != nil {
						log.Debugf("EvtNext cannot get events (Channel:%s Errno: %d): %s", channel, err.(syscall.Errno), err)
						switch err.(syscall.Errno) {
						case win32.ERROR_NO_MORE_ITEMS:
						default:
							log.Errorf("EvtNext cannot get events (Channel: %s): %s", channel, err)
						}
						// if we break when there is no events we go into an endless loop
						// because event always receive WAIT_TIMEOUT so we replaced by a
						// simple sleep followed by a continue and it works fine
						time.Sleep(1 * time.Second)
						continue
					}

					// Looping over the events retrieved
					for _, event := range events {

						// Render event to XML
						data, err := EvtRenderXML(event)
						if err != nil {
							log.Errorf("Cannot Render event to XML: %s", err)
							log.Debugf("Partial Event: %s", data)
						}

						// Convert event to UTF8 before being processed by xml.Unmarshal
						dataUTF8 := win32.UTF16BytesToString(data)
						e := XMLEvent{}
						err = xml.Unmarshal([]byte(dataUTF8), &e)
						if err != nil {
							log.Errorf("Cannot unmarshal event: %s", err)
							log.Debugf("Event unmarshal failure: %s", dataUTF8)
						}
						// Pushing reference to XMLEvent into the channel
						c <- &e

						// Close the event anyway
						// Recommended: https://msdn.microsoft.com/en-us/library/windows/desktop/aa385344(v=vs.85).aspx
						EvtClose(event)
					}
				}
				err = kernel32.ResetEvent(event)
				if err != nil {
					log.Errorf("Failed to reset event: %s", err)
					return
				}
			}
		}
	}()

	return
}
