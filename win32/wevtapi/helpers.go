package wevtapi

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"syscall"
	"win32"
	"win32/kernel32"

	"github.com/0xrawsec/golang-utils/log"
)


///////////////////////////////// XMLMap ///////////////////////////////////////
// Code adapted from source
// Source: https://stackoverflow.com/questions/30928770/marshall-map-to-xml-in-go#33110881
// Source: https://play.golang.org/p/4Z2C-GF0E7

type XMLMap map[string]interface{}

type xmlMapEntry struct {
	XMLName  xml.Name
	Value    string `xml:",chardata"`
	InnerXML string `xml:",innerxml"`
}

// MarshalXML marshals the map to XML, with each key in the map being a
// tag and it's corresponding value being it's contents.
/*func (m XMLMap) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if len(m) == 0 {
		return nil
	}

	err := e.EncodeToken(start)
	if err != nil {
		return err
	}

	for k, v := range m {
		e.Encode(xmlMapEntry{XMLName: xml.Name{Local: k}, Value: v})
	}

	return e.EncodeToken(start.End())
}*/

// UnmarshalXML unmarshals the XML into a map of string to strings,
// creating a key in the map for each tag and setting it's value to the
// tags contents.
//
// The fact this function is on the pointer of Map is important, so that
// if m is nil it can be initialized, which is often the case if m is
// nested in another xml structurel. This is also why the first thing done
// on the first line is initialize it.
func (m *XMLMap) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*m = XMLMap{}
	for {
		var e xmlMapEntry

		err := d.Decode(&e)
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if e.InnerXML != "" {
			var sm XMLMap
			r := bytes.NewBuffer([]byte(e.InnerXML))
			dec := xml.NewDecoder(r)
			err := sm.UnmarshalXML(dec, xml.StartElement{})

			if err == io.EOF {
				break
			} else if err != nil {
				return err
			}
			(*m)[e.XMLName.Local] = sm
		}
		if e.Value != "" {
			(*m)[e.XMLName.Local] = e.Value
		}
	}
	return nil
}

///////////////////////////////// XMLEvent /////////////////////////////////////

type Data struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",innerxml"`
} //`xml:"Data"`

type XMLEvent struct {
	// seems to always have the same format
	// if not consider using XMLMap
	EventData struct {
		Data []Data
	} `xml:"EventData,omitempty"`
	// Using XMLMap type because we don't know what is inside (a priori)
	UserData XMLMap
	System   struct {
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

// ToMap converts an XMLEvent to an accurate structure to be serialized
// we EventData / UserData does not appear if empty
func (xe *XMLEvent) ToMap() *map[string]interface{} {
	m := make(map[string]interface{})
	m["Event"] = make(map[string]interface{})
	if len(xe.EventData.Data) > 0 {
		m["Event"].(map[string]interface{})["EventData"] = make(map[string]interface{})
		for _, d := range xe.EventData.Data {
			m["Event"].(map[string]interface{})["EventData"].(map[string]interface{})[d.Name] = d.Value
		}
	}
	if len(xe.UserData) > 0 {
		m["Event"].(map[string]interface{})["UserData"] = xe.UserData
	}
	m["Event"].(map[string]interface{})["System"] = xe.System
	return &m
}

func (xe *XMLEvent) ToJSONEvent() *JSONEvent {
	je := NewJSONEvent()
	for _, d := range xe.EventData.Data {
		je.Event.EventData[d.Name] = d.Value
	}
	je.Event.UserData = xe.UserData
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
		UserData  map[string]interface{}
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

func enumerateEvents(sub EVT_HANDLE, channel string, signal chan bool, out chan *XMLEvent) (err error) {
	for {
		// Check if we received a signal to stop
		if _, got := GotSignal(signal); got {
			// Return error sucess
			// This will terminate polling loop
			return syscall.Errno(0)
		}

		// Try to get events
		events, err := EvtNext(sub, win32.INFINITE)
		if err != nil {
			log.Debugf("EvtNext cannot get events (Channel:%s Errno: %d): %s", channel, err.(syscall.Errno), err)
			return err
		}

		// Looping over the events retrieved
		for _, evt := range events {

			// Render event to XML
			data, err := EvtRenderXML(evt)
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
			out <- &e

			// Close the event anyway
			// Recommended: https://msdn.microsoft.com/en-us/library/windows/desktop/aa385344(v=vs.85).aspx
			EvtClose(evt)
		}
	}
}

// GetAllEventsFromChannel returns a Go channel containing XMLEvents retrieved
// from the given Windows Event Channel given in parameter
// flag has to be a value from enum EVT_SUBSCRIBE_FLAGS (c.f. headers.go)
// signal is used to stop the collection process
// Translated from source: https://msdn.microsoft.com/en-us/library/windows/desktop/aa385771(v=vs.85).aspx
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

	PollLoop:
		for {
			rc := kernel32.WaitForSingleObject(event, win32.DWORD(100))
			switch rc {
			case win32.WAIT_TIMEOUT:
				log.Debugf("Timeout waiting for events, (Channel: %s): 0x%08x", channel, rc)
				// Check if we received a signal to stop
				if _, got := GotSignal(signal); got {
					return
				}

			case win32.WAIT_OBJECT_0:
				log.Debugf("Events are ready, (Channel: %s): 0x%08x", channel, rc)
				// We need to ResetEvent asap
				// My theory why MS code does not work for high freq events:
				// If we reset after enumerating, the event might get into a signalled state (by the publisher)
				// between enumerateEvents and ResetEvent. This means that Resetting events
				// creates a deadlock (publisher will not put in a signalled state because it thinks
				// it did it already and we reset the event) so WaitForSingleObject will return
				// only timeouts. Took a while to find this explaination ...
				kernel32.ResetEvent(event)
				if err := enumerateEvents(sub, channel, signal, c); err.(syscall.Errno) != win32.ERROR_NO_MORE_ITEMS {
					// If != of Exit Success
					if err.(syscall.Errno) != 0 {
						log.Errorf("Failed to enumerate events: %s", err)
					}
					break PollLoop
				}
			}
		}
	}()
	return
}
