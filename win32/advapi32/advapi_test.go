//go:build windows
// +build windows

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
	if p, err := ParseRegValue(data, dtype); err != nil {
		t.Error(err)
	} else {
		t.Logf("Parsed Data: %v", p)
	}
}

func parseRegValueOrPanic(path string) interface{} {
	data, dtype, err := RegGetValueFromString(path)
	if err != nil {
		panic(err)
	}

	if p, err := ParseRegValue(data, dtype); err != nil {
		panic(err)
	} else {
		return p
	}
}

func TestParseRegValue(t *testing.T) {
	bfRoot := `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\`
	keys := []string{
		`HKLM\SYSTEM\CurrentControlSet\Control\EarlyStartServices`,
		bfRoot + `BuildBranch`,
		bfRoot + `BaseBuildRevisionNumber`,
		bfRoot + `BuildLabEx`,
		bfRoot + `DigitalProductId`,
		bfRoot + `ProductName`,
		bfRoot + `EditionSubVersion`,
	}

	for _, key := range keys {
		t.Logf("%s: %v", key, parseRegValueOrPanic(key))
	}
}

func TestRegGetValueSizeFromString(t *testing.T) {
	reg := "HKLM\\SYSTEM\\CurrentControlSet\\Control\\EarlyStartServices"
	size, err := RegGetValueSizeFromString(reg)
	if err != nil {
		t.Error(err)
	}
	t.Logf("Registry value size: %d", size)

}
