// +build windows,386

package win32

const (
	SIZE_OF_80387_REGISTERS     = 80
	MAXIMUM_SUPPORTED_EXTENSION = 512

	CONTEXT_i386 = 0x00010000
	CONTEXT_i486 = 0x00010000

	CONTEXT_CONTROL            = (CONTEXT_i386 | 0x00000001)
	CONTEXT_INTEGER            = (CONTEXT_i386 | 0x00000002)
	CONTEXT_SEGMENTS           = (CONTEXT_i386 | 0x00000004)
	CONTEXT_FLOATING_POINT     = (CONTEXT_i386 | 0x00000008)
	CONTEXT_DEBUG_REGISTERS    = (CONTEXT_i386 | 0x00000010)
	CONTEXT_EXTENDED_REGISTERS = (CONTEXT_i386 | 0x00000020)

	CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)

	CONTEXT_ALL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS)
)

type PCONTEXT *CONTEXT
type LPCONTEXT PCONTEXT

type MemoryBasicInformation struct {
	BaseAddress       PVOID
	AllocationBase    PVOID
	AllocationProtect DWORD
	RegionSize        SIZE_T
	State             DWORD
	Protect           DWORD
	Type              DWORD
}

type FLOATING_SAVE_AREA struct {
	ControlWord   DWORD
	StatusWord    DWORD
	TagWord       DWORD
	ErrorOffset   DWORD
	ErrorSelector DWORD
	DataOffset    DWORD
	DataSelector  DWORD
	RegisterArea  [SIZE_OF_80387_REGISTERS]byte
	Cr0NpxState   DWORD
}

type CONTEXT struct {
	ContextFlags      DWORD
	Dr0               DWORD
	Dr1               DWORD
	Dr2               DWORD
	Dr3               DWORD
	Dr6               DWORD
	Dr7               DWORD
	FloatSave         FLOATING_SAVE_AREA
	SegGs             DWORD
	SegFs             DWORD
	SegEs             DWORD
	SegDs             DWORD
	Edi               DWORD
	Esi               DWORD
	Ebx               DWORD
	Edx               DWORD
	Ecx               DWORD
	Eax               DWORD
	Ebp               DWORD
	Eip               DWORD
	SegCs             DWORD
	EFlags            DWORD
	Esp               DWORD
	SegSs             DWORD
	ExtendedRegisters [MAXIMUM_SUPPORTED_EXTENSION]byte
}
