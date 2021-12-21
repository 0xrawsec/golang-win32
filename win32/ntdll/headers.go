// +build windows

package ntdll

import (
	"fmt"

	"github.com/0xrawsec/golang-win32/win32"
)

type PROCESS_BASIC_INFORMATION struct {
	ExitStatus                   win32.NTSTATUS
	PebBaseAddress               win32.PPEB
	AffinityMask                 win32.KAFFINITY
	BasePriority                 win32.KPRIORITY
	UniqueProcessId              win32.ULONG_PTR
	InheritedFromUniqueProcessId win32.ULONG_PTR
}

type UNICODE_STRING struct {
	Length        win32.USHORT
	MaximumLength win32.USHORT
	Buffer        win32.PWSTR
}

func (u *UNICODE_STRING) String() string {
	return fmt.Sprintf("Length: %d MaximumLength: %d", u.Length, u.MaximumLength)
}

type OBJECT_ATTRIBUTES struct {
	Length                   win32.ULONG
	RootDirectory            win32.HANDLE
	ObjectName               *UNICODE_STRING
	Attributes               win32.ULONG
	SecurityDescriptor       win32.PVOID
	SecurityQualityOfService win32.PVOID
}

type IO_STATUS_BLOCK struct {
	Union       win32.PVOID
	Information win32.ULONG_PTR
}

func (i *IO_STATUS_BLOCK) Status() win32.NTSTATUS {
	return win32.NTSTATUS(i.Union)
}

func (i *IO_STATUS_BLOCK) Pointer() win32.PVOID {
	return win32.PVOID(i.Union)
}

type FILE_LINK_INFORMATION struct {
	ReplaceIfExists win32.BOOLEAN
	RootDirectory   win32.HANDLE
	FileNameLength  win32.ULONG
	FileName        win32.WCHAR
}

const (
	OBJ_INHERIT            = 0x00000002
	OBJ_PERMANENT          = 0x00000010
	OBJ_EXCLUSIVE          = 0x00000020
	OBJ_CASE_INSENSITIVE   = 0x00000040
	OBJ_OPENIF             = 0x00000080
	OBJ_OPENLINK           = 0x00000100
	OBJ_KERNEL_HANDLE      = 0x00000200
	OBJ_FORCE_ACCESS_CHECK = 0x00000400
	OBJ_VALID_ATTRIBUTES   = 0x000007F2

	FileDirectoryInformation = iota + 1
	FileFullDirectoryInformation
	FileBothDirectoryInformation
	FileBasicInformation
	FileStandardInformation
	FileInternalInformation
	FileEaInformation
	FileAccessInformation
	FileNameInformation
	FileRenameInformation
	FileLinkInformation
	FileNamesInformation
	FileDispositionInformation
	FilePositionInformation
	FileFullEaInformation
	FileModeInformation
	FileAlignmentInformation
	FileAllInformation
	FileAllocationInformation
	FileEndOfFileInformation
	FileAlternateNameInformation
	FileStreamInformation
	FilePipeInformation
	FilePipeLocalInformation
	FilePipeRemoteInformation
	FileMailslotQueryInformation
	FileMailslotSetInformation
	FileCompressionInformation
	FileObjectIdInformation
	FileCompletionInformation
	FileMoveClusterInformation
	FileQuotaInformation
	FileReparsePointInformation
	FileNetworkOpenInformatio
	FileAttributeTagInformation
	FileTrackingInformation
	FileIdBothDirectoryInformation
	FileIdFullDirectoryInformation
	FileValidDataLengthInformation

	FileShortNameInformation           = 40
	FileSfioReserveInformation         = 44
	FileSfioVolumeInformation          = 45
	FileHardLinkInformation            = 46
	FileNormalizedNameInformation      = 48
	FileIdGlobalTxDirectoryInformation = 50
	FileStandardLinkInformation        = 54

	FileMaximumInformation

	DELETE       = 0x00010000
	READ_CONTROL = 0x00020000
	WRITE_DAC    = 0x00040000
	WRITE_OWNER  = 0x00080000
	SYNCHRONIZE  = 0x00100000

	STANDARD_RIGHTS_REQUIRED = 0x000F0000

	STANDARD_RIGHTS_READ    = READ_CONTROL
	STANDARD_RIGHTS_WRITE   = READ_CONTROL
	STANDARD_RIGHTS_EXECUTE = READ_CONTROL

	STANDARD_RIGHTS_ALL = 0x001F0000

	SPECIFIC_RIGHTS_ALL = 0x0000FFFF

	ACCESS_SYSTEM_SECURITY = 0x01000000
	MAXIMUM_ALLOWED        = 0x02000000

	GENERIC_READ    = 0x80000000
	GENERIC_WRITE   = 0x40000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL     = 0x10000000

	FILE_SHARE_READ                    = 0x00000001
	FILE_SHARE_WRITE                   = 0x00000002
	FILE_SHARE_DELETE                  = 0x00000004
	FILE_SHARE_VALID_FLAGS             = 0x00000007
	FILE_ATTRIBUTE_READONLY            = 0x00000001
	FILE_ATTRIBUTE_HIDDEN              = 0x00000002
	FILE_ATTRIBUTE_SYSTEM              = 0x00000004
	FILE_ATTRIBUTE_DIRECTORY           = 0x00000010
	FILE_ATTRIBUTE_ARCHIVE             = 0x00000020
	FILE_ATTRIBUTE_DEVICE              = 0x00000040
	FILE_ATTRIBUTE_NORMAL              = 0x00000080
	FILE_ATTRIBUTE_TEMPORARY           = 0x00000100
	FILE_ATTRIBUTE_SPARSE_FILE         = 0x00000200
	FILE_ATTRIBUTE_REPARSE_POINT       = 0x00000400
	FILE_ATTRIBUTE_COMPRESSED          = 0x00000800
	FILE_ATTRIBUTE_OFFLINE             = 0x00001000
	FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000
	FILE_ATTRIBUTE_ENCRYPTED           = 0x00004000
	FILE_ATTRIBUTE_VIRTUAL             = 0x00010000
	FILE_NOTIFY_CHANGE_FILE_NAME       = 0x00000001
	FILE_NOTIFY_CHANGE_DIR_NAME        = 0x00000002
	FILE_NOTIFY_CHANGE_ATTRIBUTES      = 0x00000004
	FILE_NOTIFY_CHANGE_SIZE            = 0x00000008
	FILE_NOTIFY_CHANGE_LAST_WRITE      = 0x00000010
	FILE_NOTIFY_CHANGE_LAST_ACCESS     = 0x00000020
	FILE_NOTIFY_CHANGE_CREATION        = 0x00000040
	FILE_NOTIFY_CHANGE_SECURITY        = 0x00000100
	FILE_ACTION_ADDED                  = 0x00000001
	FILE_ACTION_REMOVED                = 0x00000002
	FILE_ACTION_MODIFIED               = 0x00000003
	FILE_ACTION_RENAMED_OLD_NAME       = 0x00000004
	FILE_ACTION_RENAMED_NEW_NAME       = 0x00000005
	// Not sure about this one
	MAILSLOT_NO_MESSAGE = -1
	// Not sure about this one
	MAILSLOT_WAIT_FOREVER             = -1
	FILE_CASE_SENSITIVE_SEARCH        = 0x00000001
	FILE_CASE_PRESERVED_NAMES         = 0x00000002
	FILE_UNICODE_ON_DISK              = 0x00000004
	FILE_PERSISTENT_ACLS              = 0x00000008
	FILE_FILE_COMPRESSION             = 0x00000010
	FILE_VOLUME_QUOTAS                = 0x00000020
	FILE_SUPPORTS_SPARSE_FILES        = 0x00000040
	FILE_SUPPORTS_REPARSE_POINTS      = 0x00000080
	FILE_SUPPORTS_REMOTE_STORAGE      = 0x00000100
	FILE_VOLUME_IS_COMPRESSED         = 0x00008000
	FILE_SUPPORTS_OBJECT_IDS          = 0x00010000
	FILE_SUPPORTS_ENCRYPTION          = 0x00020000
	FILE_NAMED_STREAMS                = 0x00040000
	FILE_READ_ONLY_VOLUME             = 0x00080000
	FILE_SEQUENTIAL_WRITE_ONCE        = 0x00100000
	FILE_SUPPORTS_TRANSACTIONS        = 0x00200000
	FILE_SUPPORTS_HARD_LINKS          = 0x00400000
	FILE_SUPPORTS_EXTENDED_ATTRIBUTES = 0x00800000
	FILE_SUPPORTS_OPEN_BY_FILE_ID     = 0x01000000
	FILE_SUPPORTS_USN_JOURNAL         = 0x02000000
	FILE_SUPPORTS_INTEGRITY_STREAMS   = 0x04000000
)

/*
typedef struct in6_addr {
	union {
	  UCHAR  Byte[16];
	  USHORT Word[8];
	} u;
  } IN6_ADDR, *PIN6_ADDR, *LPIN6_ADDR;
*/

type In6Addr struct {
	u [16]byte
}
