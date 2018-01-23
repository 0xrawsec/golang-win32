// +build windows,amd64

package win32

const (
	CONTEXT_AMD64 = 0x100000

	CONTEXT_CONTROL         = (CONTEXT_AMD64 | 0x1)
	CONTEXT_INTEGER         = (CONTEXT_AMD64 | 0x2)
	CONTEXT_SEGMENTS        = (CONTEXT_AMD64 | 0x4)
	CONTEXT_FLOATING_POINT  = (CONTEXT_AMD64 | 0x8)
	CONTEXT_DEBUG_REGISTERS = (CONTEXT_AMD64 | 0x10)

	CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
	CONTEXT_ALL  = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)

	CONTEXT_EXCEPTION_ACTIVE    = 0x8000000
	CONTEXT_SERVICE_ACTIVE      = 0x10000000
	CONTEXT_EXCEPTION_REQUEST   = 0x40000000
	CONTEXT_EXCEPTION_REPORTING = 0x80000000
)

type PCONTEXT *CONTEXT
type LPCONTEXT PCONTEXT

type MemoryBasicInformation struct {
	BaseAddress       ULONGLONG
	AllocationBase    ULONGLONG
	AllocationProtect DWORD
	Alignment1        DWORD
	RegionSize        ULONGLONG
	State             DWORD
	Protect           DWORD
	Type              DWORD
	Alignment2        DWORD
}

type M128A struct {
	Low  ULONGLONG
	High LONGLONG
}

type XMM_SAVE_AREA32 struct {
	ControlWord    WORD
	StatusWord     WORD
	TagWord        BYTE
	Reserved1      BYTE
	ErrorOpcode    WORD
	ErrorOffset    DWORD
	ErrorSelector  WORD
	Reserved2      WORD
	DataOffset     DWORD
	DataSelector   WORD
	Reserved3      WORD
	MxCsr          DWORD
	MxCsr_Mask     DWORD
	FloatRegisters [8]M128A
	XmmRegisters   [16]M128A
	Reserved4      [96]BYTE
}

type CONTEXT struct {
	P1Home               DWORD64
	P2Home               DWORD64
	P3Home               DWORD64
	P4Home               DWORD64
	P5Home               DWORD64
	P6Home               DWORD64
	ContextFlags         DWORD
	MxCsr                DWORD
	SegCs                WORD
	SegDs                WORD
	SegEs                WORD
	SegFs                WORD
	SegGs                WORD
	SegSs                WORD
	EFlags               DWORD
	Dr0                  DWORD64
	Dr1                  DWORD64
	Dr2                  DWORD64
	Dr3                  DWORD64
	Dr6                  DWORD64
	Dr7                  DWORD64
	Rax                  DWORD64
	Rcx                  DWORD64
	Rdx                  DWORD64
	Rbx                  DWORD64
	Rsp                  DWORD64
	Rbp                  DWORD64
	Rsi                  DWORD64
	Rdi                  DWORD64
	R8                   DWORD64
	R9                   DWORD64
	R10                  DWORD64
	R11                  DWORD64
	R12                  DWORD64
	R13                  DWORD64
	R14                  DWORD64
	R15                  DWORD64
	Rip                  DWORD64
	FloatSave            XMM_SAVE_AREA32 // Is a union normaly I kept only the biggest struct in it since it is supposed to work
	VectorRegister       [26]M128A
	VectorControl        DWORD64
	DebugControl         DWORD64
	LastBranchToRip      DWORD64
	LastBranchFromRip    DWORD64
	LastExceptionToRip   DWORD64
	LastExceptionFromRip DWORD64
}
