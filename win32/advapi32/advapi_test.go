package advapi32

import (
	"bytes"
	"encoding/csv"
	"math/rand"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/0xrawsec/golang-utils/log"
)

var (
	DNSGuid, _ = GUIDFromString("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}")
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
	sessionProperties.Wnode.Guid = GUID{} // To set
	sessionProperties.Wnode.ClientContext = 0
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
	log.Infof("BufferCallback")
	return 1
}

func EvtRecCb(er *EventRecord) uintptr {
	log.Infof("EventRecord received: %d", er.UserDataLength)
	log.Infof("EventRecord received: %t", er.EventHeader.Flags&EVENT_HEADER_FLAG_STRING_ONLY == EVENT_HEADER_FLAG_STRING_ONLY)
	log.Infof("EventProperty = 0x%08x", er.EventHeader.EventProperty)
	log.Infof("EventPropertyXML = %t", er.EventHeader.EventProperty == EVENT_HEADER_PROPERTY_XML)
	return 0
}

func TestEnableTraceEx2(t *testing.T) {
	var sessionHandle uintptr
	var loggerInfo EventTraceLogfile

	rand.Seed(time.Now().Unix())

	//logSessionName := fmt.Sprintf("TestStartTraceGolangPOC%d", rand.Uint32())
	logSessionName := "TestStartTraceGolangPOC"
	log.Infof("Log Session Name: %s", logSessionName)

	sessionProperties := NewRealTimeSessionProperty(logSessionName)

	err := StartTrace(&sessionHandle, syscall.StringToUTF16Ptr(logSessionName), sessionProperties)

	if err != nil {
		t.Errorf("Failed to create trace: %s", err)
	}
	defer ControlTrace(sessionHandle, nil, sessionProperties, EVENT_TRACE_CONTROL_STOP)
	if !checkSessionRunning(logSessionName) {
		t.Errorf("Session is not running")
	}

	t.Logf("Enabling Trace on GUID: %s", DNSGuid)
	if err := EnableTraceEx2(
		sessionHandle,
		DNSGuid,
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		TRACE_LEVEL_VERBOSE,
		0xffffffffffffffff,
		0,
		0,
		nil,
	); err != nil {
		t.Errorf("Failed to enable trace: %s", err)
		t.FailNow()
	}
	defer EnableTraceEx2(sessionHandle, DNSGuid, EVENT_CONTROL_CODE_DISABLE_PROVIDER, 0, 0, 0, 0, nil)

	// Consumer Part
	loggerInfo.SetProcessTraceMode(PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP | PROCESS_TRACE_MODE_REAL_TIME)
	loggerInfo.BufferCallback = syscall.NewCallback(BuffCB)
	loggerInfo.Callback = syscall.NewCallback(EvtRecCb)
	loggerInfo.Context = 0
	loggerInfo.LoggerName = syscall.StringToUTF16Ptr(logSessionName)

	traceHandle, err := OpenTrace(&loggerInfo)
	if err != nil {
		t.Errorf("Failed to open trace: %s", err)
		t.FailNow()
	}

	go func() {
		if err := ProcessTrace(&traceHandle, 1, nil, nil); err != nil {
			t.Errorf("Failed to process trace: %s", err)
			t.FailNow()
		}
	}()

	time.Sleep(60 * time.Second)
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
