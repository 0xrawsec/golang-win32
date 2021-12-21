// +build windows

package advapi32

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
)

var (
	DNSGuid, _                = GUIDFromString("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}")
	SysmonGuid, _             = GUIDFromString("{5770385F-C22A-43E0-BF4C-06F5698FFBD9}")
	COMGuid, _                = GUIDFromString("{D4263C98-310C-4D97-BA39-B55354F08584}")
	KernelMemoryGUID, _       = GUIDFromString("{D1D93EF7-E1F2-4F45-9943-03D245FE6C00}")
	SecurityAuditing, _       = GUIDFromString("{54849625-5478-4994-A5BA-3E3B0328C30D}")
	URLMon, _                 = GUIDFromString("{245F975D-909D-49ED-B8F9-9A75691D6B6B}")
	Microsoft_Windows_Ntfs, _ = GUIDFromString("{3FF37A1C-A68D-4D6E-8C9B-F79E8B16C482}")
	Ntfs, _                   = GUIDFromString("{DD70BC80-EF44-421B-8AC3-CD31DA613A4E}")
)

func MakeSessionProperty(sessionName string) (*EventTraceProperties, uint32) {
	size := ((len(sessionName) + 1) * 2) + int(unsafe.Sizeof(EventTraceProperties{}))
	s := make([]byte, size)
	return (*EventTraceProperties)(unsafe.Pointer(&s[0])), uint32(size)
}

func NewRealTimeSessionProperty(logSessionName string) *EventTraceProperties {
	sessionProperties, size := MakeSessionProperty(logSessionName)

	// Necessary fields for SessionProperties struct
	sessionProperties.Wnode.BufferSize = size
	sessionProperties.Wnode.Guid = GUID{}     // To set
	sessionProperties.Wnode.ClientContext = 1 // QPC
	sessionProperties.Wnode.Flags = WNODE_FLAG_ALL_DATA
	sessionProperties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
	sessionProperties.LogFileNameOffset = 0
	sessionProperties.LoggerNameOffset = uint32(unsafe.Sizeof(EventTraceProperties{}))

	return sessionProperties
}

func checkSessionRunning(sname string) bool {
	cmd := exec.Command("logman", "query", sname, "-ets")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorf("Failed to run command line: %s", err)
		return false
	}
	return bytes.Index(out, []byte(sname)) != 1
}

func TestGuid(t *testing.T) {
	dnsClientGuid := "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
	guid, err := GUIDFromString(dnsClientGuid)
	if err != nil {
		t.Errorf("Failed to parse guid: %s", err)
	}
	if guid.String() != dnsClientGuid {
		t.Errorf("%s != %s (original)", guid, dnsClientGuid)
	}
	t.Log(guid)
}

func TestStartTrace(t *testing.T) {
	var sessionHandle uintptr
	logSessionName := "TestStartTraceGolangPOC"

	sessionProperties := NewRealTimeSessionProperty(logSessionName)

	err := StartTrace(&sessionHandle, syscall.StringToUTF16Ptr(logSessionName), sessionProperties)

	if err != nil {
		t.Errorf("Failed to create trace: %s", err)
	}
	defer ControlTrace(sessionHandle, nil, sessionProperties, EVENT_TRACE_CONTROL_STOP)
	if !checkSessionRunning(logSessionName) {
		t.Errorf("Session is not running")
	}
}

func BuffCB(e *EventTraceLogfile) uintptr {
	//log.Infof("BufferCallback")
	// We must return True otherwise the trace stops
	return 1
}

var (
	decSource = []string{"XML instrumentation manifest", "WMI MOF class", "WPP TMF file"}
)

type EventRecordHelper struct {
	Event      *EventRecord
	TraceInfo  *TraceEventInfo
	userDataIt uintptr
}

func NewEventRecordHelper(er *EventRecord) (erh *EventRecordHelper, err error) {
	erh = &EventRecordHelper{}
	erh.Event = er
	if erh.TraceInfo, err = GetEventInformation(er); err != nil {
		return
	}
	erh.userDataIt = er.UserData
	return
}

func (e *EventRecordHelper) PointerSize() uint32 {
	if e.Event.EventHeader.Flags&EVENT_HEADER_FLAG_32_BIT_HEADER == EVENT_HEADER_FLAG_32_BIT_HEADER {
		return 4
	}
	return 8
}

func (e *EventRecordHelper) EventID() int {
	if e.TraceInfo.DecodingSource == DecodingSourceXMLFile {
		return int(e.TraceInfo.EventDescriptor.Id)
	}
	// not meaningful, cannot be used to identify event
	return -1
}

func (e *EventRecordHelper) EndUserData() uintptr {
	return e.Event.UserData + uintptr(e.Event.UserDataLength)
}

func (e *EventRecordHelper) UserDataLength() uint16 {
	return uint16(e.EndUserData() - e.userDataIt)
}

func (e *EventRecordHelper) GetPropertyLength(i uint32) (uint32, error) {
	if epi := e.TraceInfo.GetEventPropertyInfoAt(i); epi.Flags&PropertyParamLength == PropertyParamLength {
		propSize := uint32(0)
		length := uint32(0)
		j := uint32(epi.LengthPropertyIndex())
		pdd := PropertyDataDescriptor{}
		pdd.PropertyName = uint64(e.TraceInfo.pointer()) + uint64(e.TraceInfo.GetEventPropertyInfoAt(j).NameOffset)
		pdd.ArrayIndex = math.MaxUint32
		if err := TdhGetPropertySize(e.Event, 0, nil, 1, &pdd, &propSize); err != nil {
			return 0, fmt.Errorf("failed to get property size: %s", err)
		} else {
			if err := TdhGetProperty(e.Event, 0, nil, 1, &pdd, propSize, (*byte)(unsafe.Pointer(&length))); err != nil {
				return 0, fmt.Errorf("failed to get property: %s", err)
			}
			return length, nil
		}
	} else {
		if epi.Length() > 0 {
			return uint32(epi.Length()), nil
		} else {
			switch {
			// if there is an error returned here just try to add a switch case
			// with the propert in type
			case epi.InType() == uint16(TdhInTypeBinary) && epi.OutType() == uint16(TdhOutTypeIpv6):
				t := win32.IN6_ADDR{}
				return uint32(len(t)), nil
			case epi.InType() == uint16(TdhInTypeUnicodestring):
				return uint32(epi.Length()), nil
			case epi.InType() == uint16(TdhInTypeAnsistring):
				return uint32(epi.Length()), nil
			case epi.InType() == uint16(TdhInTypeSid):
				return uint32(epi.Length()), nil
			case epi.InType() == uint16(TdhInTypeWbemsid):
				return uint32(epi.Length()), nil
			case epi.Flags&PropertyStruct == PropertyStruct:
				return uint32(epi.Length()), nil
			default:
				return 0, fmt.Errorf("unexpected length of 0 for intype %d and outtype %d", epi.InType(), epi.OutType())
			}
		}
	}
}

func (e *EventRecordHelper) GetArraySize(i uint32) (arraySize uint16, err error) {
	dataDesc := PropertyDataDescriptor{}
	propSz := uint32(0)

	epi := e.TraceInfo.GetEventPropertyInfoAt(i)
	if (epi.Flags & PropertyParamCount) == PropertyParamCount {
		count := uint32(0)
		j := epi.CountUnion
		dataDesc.PropertyName = uint64(e.TraceInfo.pointer() + uintptr(e.TraceInfo.GetEventPropertyInfoAt(uint32(j)).NameOffset))
		dataDesc.ArrayIndex = math.MaxUint32
		if err = TdhGetPropertySize(e.Event, 0, nil, 1, &dataDesc, &propSz); err != nil {
			return
		}
		if err = TdhGetProperty(e.Event, 0, nil, 1, &dataDesc, propSz, ((*byte)(unsafe.Pointer(&count)))); err != nil {
			return
		}
		arraySize = uint16(count)
	} else {
		arraySize = epi.CountUnion
	}
	return
}

func (e *EventRecordHelper) ParseProperty(i uint32) (name, value string, err error) {
	var mapInfo *EventMapInfo
	var propertyLength uint32
	var udc uint16
	var buff []uint16

	epi := e.TraceInfo.GetEventPropertyInfoAt(i)
	formattedDataSize := uint32(64)

	// Get the name/value mapping if the property specifies a value map.
	if epi.MapNameOffset() > 0 {
		pMapName := (*uint16)(unsafe.Pointer(e.TraceInfo.pointerOffset(uintptr(epi.MapNameOffset()))))
		if mapInfo, err = GetMapInfo(e.Event, pMapName, uint32(e.TraceInfo.DecodingSource)); err != nil {
			err = fmt.Errorf("failed to get map info: %s", err)
			return
		}
	}

	if propertyLength, err = e.GetPropertyLength(i); err != nil {
		err = fmt.Errorf("failed to get property length: %s", err)
		return
	}

	for {
		buff = make([]uint16, formattedDataSize)

		err = TdhFormatProperty(
			e.TraceInfo,
			mapInfo,
			e.PointerSize(),
			epi.InType(),
			epi.OutType(),
			uint16(propertyLength),
			e.UserDataLength(),
			(*byte)(unsafe.Pointer(e.userDataIt)),
			&formattedDataSize,
			&buff[0],
			&udc)

		if err == syscall.ERROR_INSUFFICIENT_BUFFER {
			continue
		}

		if err == syscall.Errno(win32.ERROR_EVT_INVALID_EVENT_DATA) {
			if mapInfo == nil {
				break
			}
			mapInfo = nil
			continue
		}

		if err == nil {
			break
		}

		err = fmt.Errorf("failed to format property : %s", err)
		break
	}

	name = win32.UTF16AtOffsetToString(e.TraceInfo.pointer(), uintptr(epi.NameOffset))
	value = syscall.UTF16ToString(buff)
	e.userDataIt += uintptr(udc)
	return
}

func (e *EventRecordHelper) ParseProperties() (event map[string]interface{}, err error) {
	var arraySize uint16
	var value, name string
	event = make(map[string]interface{})

	for i := uint32(0); i < e.TraceInfo.TopLevelPropertyCount; i++ {
		//pUserData = PrintProperties(er, tei, pointerSize, i, pUserData, pEndOfUserData)
		epi := e.TraceInfo.GetEventPropertyInfoAt(i)
		isArray := epi.Flags&PropertyParamCount == PropertyParamCount
		switch {
		case isArray:
			log.Debugf("Property is an array")
		case epi.Flags&PropertyParamLength == PropertyParamLength:
			log.Debugf("Property is a buffer")
		case epi.Flags&PropertyParamCount == PropertyStruct:
			log.Debugf("Property is a struct")
		default:
			// property is a map
		}

		if arraySize, err = e.GetArraySize(i); err != nil {
			return
		} else {
			var arrayName string
			var array []interface{}

			// this is not because we have arraySize > 0 that we are an array
			// so if we deal with an array property
			if isArray {
				array = make([]interface{}, 0)
			}

			for k := uint16(0); k < arraySize; k++ {
				// If the property is a structure, print the members of the structure.
				if epi.Flags&PropertyStruct == PropertyStruct {
					log.Debugf("structure over here")
					propStruct := make(map[string]interface{})
					lastMember := epi.StructStartIndex() + epi.NumOfStructMembers()
					for j := epi.StructStartIndex(); j < lastMember; j++ {
						log.Debugf("parsing struct property: %d", j)
						if name, value, err = e.ParseProperty(uint32(j)); err != nil {
							return
						} else {
							propStruct[name] = value
						}
					}
					if isArray {
						arrayName = "Structures"
						array = append(array, propStruct)
					}
				} else {
					if name, value, err = e.ParseProperty(i); err != nil {
						return
					} else {
						if isArray {
							arrayName = name
							array = append(array, value)
						} else {
							event[name] = value
						}
					}
				}
			}

			if isArray {
				event[arrayName] = array
			}
		}
	}
	if _, ok := event["ProcessId"]; !ok {
		event["ProcessId"] = fmt.Sprintf("%d", e.Event.EventHeader.ProcessId)
	}
	if _, ok := event["ThreadId"]; !ok {
		event["ThreadId"] = fmt.Sprintf("%d", e.Event.EventHeader.ThreadId)
	}
	if _, ok := event["EventID"]; !ok {
		event["EventID"] = fmt.Sprintf("%d", e.TraceInfo.EventDescriptor.Id)
	}
	if _, ok := event["Provider"]; !ok {
		event["Provider"] = fmt.Sprintf("%s", e.TraceInfo.ProviderGuid.String())
	}
	return
}

func NewEvtRecCb(er *EventRecord) uintptr {
	if h, err := NewEventRecordHelper(er); err == nil {
		if event, err := h.ParseProperties(); err != nil {
			log.Errorf("Failed to parse properties: %s", err)
		} else if b, err := json.Marshal(event); err == nil {
			log.Info(string(b))
		}
	}
	return 0
}

func EvtRecCb(er *EventRecord) uintptr {
	/*log.Infof("EventRecord (size:0x%x): %v", unsafe.Sizeof(*er), *er)
	log.Infof("sizeof(EventHeader)=0x%x", unsafe.Sizeof(*&er.EventHeader))
	log.Infof("sizeof(BufferContext)=0x%x", unsafe.Sizeof(*&er.BufferContext))
	log.Infof("sizeof(ExtendedData)=0x%x", unsafe.Sizeof(*&er.ExtendedData))
	log.Infof("pUserData: 0x%08x", er.UserData)
	log.Infof("UserDataLength: %d", er.UserDataLength)
	log.Infof("EventRecord received: %t", er.EventHeader.Flags&EVENT_HEADER_FLAG_STRING_ONLY == EVENT_HEADER_FLAG_STRING_ONLY)
	log.Infof("EventProperty = 0x%08x", er.EventHeader.EventProperty)
	log.Infof("EventPropertyXML = %t", er.EventHeader.EventProperty == EVENT_HEADER_PROPERTY_XML)*/
	tei, err := GetEventInformation(er)
	if err != nil {
		log.Errorf("Failed to get EventRecord information: %s", err)
	} else {
		/*
			log.Infof("Provider GUID: %s", tei.ProviderGuid.String())
			log.Infof("Decoding source: %s", decSource[tei.DecodingSource])
			log.Infof("Decoding source: %d", tei.DecodingSource)
			log.Infof("Level name: %s", tei.LevelName())
			log.Infof("Provider name: %s", tei.ProviderName())
			log.Infof("Channel name: %s", tei.ChannelName())
			log.Infof("Event Message: %s", tei.EventMessage())
			log.Infof("Activity ID name: %s", tei.ActivityIDName())
			log.Infof("Related activity ID name: %s", tei.RelatedActivityIDName())
			log.Infof("Number of top-level properties: %d", tei.TopLevelPropertyCount)
			log.Infof("Total number of properties: %d", tei.PropertyCount)*/

		if tei.DecodingSource == DecodingSourceXMLFile {
			log.Infof("\nEvent ID: %d", tei.EventDescriptor.Id)
		}

	}
	return 0
}

func NewRealTimeKernelSessionProperty() (p *EventTraceProperties) {
	p = NewRealTimeSessionProperty("NT Kernel Logger")
	p.Wnode.Guid = *SystemTraceControlGuid
	return
}

func TestEnableTraceEx2(t *testing.T) {
	var sessionHandle uintptr
	var loggerInfo EventTraceLogfile

	rand.Seed(time.Now().Unix())

	//logSessionName := "TestStartTraceGolangPOC"
	logSessionName := "NT Kernel Logger"
	log.Infof("Log Session Name: %s", logSessionName)

	sessionProperties := NewRealTimeSessionProperty(logSessionName)
	sessionProperties.Wnode.Guid = *SystemTraceControlGuid
	// to enable kernel logging
	//sessionProperties.EnableFlags |= EVENT_TRACE_SYSTEM_LOGGER_MODE
	sessionProperties.EnableFlags |= EVENT_TRACE_FLAG_PROCESS_COUNTERS
	sessionProperties.EnableFlags |= EVENT_TRACE_FLAG_PROCESS_COUNTERS
	//sessionProperties.EnableFlags |= EVENT_TRACE_FLAG_DRIVER

	err := StartTrace(&sessionHandle, syscall.StringToUTF16Ptr(logSessionName), sessionProperties)

	if err != nil {
		t.Errorf("Failed to create trace: %s", err)
	}
	defer ControlTrace(sessionHandle, nil, sessionProperties, EVENT_TRACE_CONTROL_STOP)

	if !checkSessionRunning(logSessionName) {
		t.Errorf("Session is not running")
	}
	/*params := EnableTraceParameters{
		Version:          2,
		FilterDescrCount: 0,
	}

	// Notes from Microsoft: https://github.com/microsoft/krabsetw/blob/master/examples/ManagedExamples/UserTrace005.cs
	// From github issue: That's right - we were told we needed to onboard to ELAM in order to create a trace session for Windows-Security-Auditing.
	// Further, only one trace session is allowed for this provider.
	// This session is created by the OS and is called 'EventLog-Security'.
	// We can't Stop this session, but we can Open a handle to it.
	guid := NTKernelLoggerProviders("ALPC")
	t.Logf("Enabling Trace on GUID: %s", guid)
	if err := EnableTraceEx2(
		sessionHandle,
		guid,
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		255, // should get all trace levels as it is the highest
		//0xffffffffffffffff,
		0x8000000000000000,
		0x0,
		0,
		&params,
	); err != nil {
		t.Errorf("Failed to enable trace: %s", err)
		t.FailNow()
	}
	defer EnableTraceEx2(sessionHandle, guid, EVENT_CONTROL_CODE_DISABLE_PROVIDER, 0, 0, 0, 0, nil)
	*/
	/*guid = DNSGuid
	if err := EnableTraceEx2(
		sessionHandle,
		guid,
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		TRACE_LEVEL_VERBOSE, // should get all trace levels as it is the highest
		0xffffffffffffffff,
		0,
		0,
		&params,
	); err != nil {
		t.Errorf("Failed to enable trace: %s", err)
		t.FailNow()
	}
	defer EnableTraceEx2(sessionHandle, guid, EVENT_CONTROL_CODE_DISABLE_PROVIDER, 0, 0, 0, 0, nil)
	*/
	// Consumer Part
	loggerInfo.SetProcessTraceMode(PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP | PROCESS_TRACE_MODE_REAL_TIME)
	loggerInfo.BufferCallback = syscall.NewCallbackCDecl(BuffCB)
	//loggerInfo.Callback = syscall.NewCallbackCDecl(EvtRecCb)
	loggerInfo.Callback = syscall.NewCallbackCDecl(NewEvtRecCb)
	loggerInfo.Context = 0
	loggerInfo.LoggerName = syscall.StringToUTF16Ptr(logSessionName)
	//loggerInfo.LoggerName = syscall.StringToUTF16Ptr("Eventlog-Security")

	traceHandle, err := OpenTrace(&loggerInfo)
	if err != nil {
		t.Errorf("Failed to open trace: %s", err)
		t.FailNow()
	}

	go func() {
		if err := kernel32.SetCurrentThreadPriority(win32.THREAD_PRIORITY_TIME_CRITICAL); err != nil {
			log.Errorf("Failed to raise  thread priority: %s", err)
		}
		// this guy can take an array of trace handles
		// solution for tracing audit logs
		if err := ProcessTrace(&traceHandle, 1, nil, nil); err != nil {
			t.Errorf("Failed to process trace: %s", err)
			t.FailNow()
		}
		log.Infof("End process trace")
	}()

	time.Sleep(30 * time.Second)
	defer CloseTrace(traceHandle)
}

func randomSvcPid() (pid uint32, service string) {
	c := exec.Command("tasklist", "/SVC", "/FO", "CSV", "/NH")

	out, err := c.Output()
	if err != nil {
		log.Errorf("Failed to run tasklist: %s", err)
		return 0, ""
	}

	r := csv.NewReader(bytes.NewBuffer(out))
	lines, err := r.ReadAll()
	if err != nil {
		log.Errorf("Failed to read tasklist output")
	}
	rand.Seed(time.Now().Unix())
	for {
		i := rand.Int() % len(lines)
		rec := lines[i]
		// Expect three fields
		if len(rec) == 3 {
			svc := rec[2]
			if svc != "N/A" {
				pid64, err := strconv.ParseUint(rec[1], 10, 32)
				if err != nil {
					log.Errorf("Failed to parse pid \"%s\"", rec[1])
				}
				return uint32(pid64), svc
			}
		}
	}

	log.Errorf("Unexpected tasklist output: %s", out)
	return 0, ""
}

var (
	// moved outside test function to have an accurate timing
	pid, expSvc = randomSvcPid()
)

func TestServiceEnumerator(t *testing.T) {

	if pid == 0 {
		t.Errorf("Failed to find a SVC to test")
		t.FailNow()
	}

	svc, err := ServiceWin32NamesByPid(pid)
	if err != nil {
		t.Errorf("Failed to get ServiceNameByPID: %s", err)
		t.FailNow()
	}

	if expSvc != svc {
		t.Fail()
	}

	nasvc, err := ServiceWin32NamesByPid(0xffffffff)
	if nasvc != "N/A" {
		t.Fail()
	}

	t.Logf("Expected: %s VS Found: %s", expSvc, svc)
	t.Logf("Non existing PID returned: %s", nasvc)

}

func TestRegGetValueFromString(t *testing.T) {
	//reg := "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateRepository\\Cache\\ApplicationExtension\\Data\\1da\\Category"
	//reg := "HKLM\\SOFTWARE\\Test"
	//reg := "HKLM\\SOFTWARE\\Binary"
	reg := "HKLM\\SYSTEM\\CurrentControlSet\\Control\\EarlyStartServices"
	data, dtype, err := RegGetValueFromString(reg)
	if err != nil {
		t.Error(err)
	}
	t.Logf("Data type: %d", dtype)
	t.Logf("Data: %q", data)
}

func TestRegGetValueSizeFromString(t *testing.T) {
	reg := "HKLM\\SYSTEM\\CurrentControlSet\\Control\\EarlyStartServices"
	size, err := RegGetValueSizeFromString(reg)
	if err != nil {
		t.Error(err)
	}
	t.Logf("Registry value size: %d", size)

}
