// +build windows

package fltlib

import (
	"syscall"
	"unsafe"
)

/*
FilterAttach API wrapper generated from prototype
HRESULT WINAPI FilterAttach(
	 LPCWSTR lpFilterName,
	 LPCWSTR lpVolumeName,
	 LPCWSTR lpInstanceName,
	 DWORD dwCreatedInstanceNameLength,
	 LPWSTR lpCreatedInstanceName);
*/
func FilterAttach(lpFilterName *uint16,
	lpVolumeName *uint16,
	lpInstanceName *uint16,
	dwCreatedInstanceNameLength uint32,
	lpCreatedInstanceName *uint16) (int32, error) {
	r1, _, err := filterAttach.Call(
		uintptr(unsafe.Pointer(lpFilterName)),
		uintptr(unsafe.Pointer(lpVolumeName)),
		uintptr(unsafe.Pointer(lpInstanceName)),
		uintptr(dwCreatedInstanceNameLength),
		uintptr(unsafe.Pointer(lpCreatedInstanceName)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterAttachAtAltitude API wrapper generated from prototype
HRESULT WINAPI FilterAttachAtAltitude(
	 LPCWSTR lpFilterName,
	 LPCWSTR lpVolumeName,
	 LPCWSTR lpAltitude,
	 LPCWSTR lpInstanceName,
	 DWORD dwCreatedInstanceNameLength,
	 LPWSTR lpCreatedInstanceName);
*/
func FilterAttachAtAltitude(lpFilterName *uint16,
	lpVolumeName *uint16,
	lpAltitude *uint16,
	lpInstanceName *uint16,
	dwCreatedInstanceNameLength uint32,
	lpCreatedInstanceName *uint16) (int32, error) {
	r1, _, err := filterAttachAtAltitude.Call(
		uintptr(unsafe.Pointer(lpFilterName)),
		uintptr(unsafe.Pointer(lpVolumeName)),
		uintptr(unsafe.Pointer(lpAltitude)),
		uintptr(unsafe.Pointer(lpInstanceName)),
		uintptr(dwCreatedInstanceNameLength),
		uintptr(unsafe.Pointer(lpCreatedInstanceName)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterClose API wrapper generated from prototype
HRESULT WINAPI FilterClose(
	 HFILTER hFilter);
*/
func FilterClose(hFilter syscall.Handle) (int32, error) {
	r1, _, err := filterClose.Call(
		uintptr(hFilter))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterConnectCommunicationPort API wrapper generated from prototype
HRESULT WINAPI FilterConnectCommunicationPort(
	 LPCWSTR lpPortName,
	 DWORD dwOptions,
	 LPCVOID lpContext,
	 WORD wSizeOfContext,
	 LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	 HANDLE *hPort);
*/
func FilterConnectCommunicationPort(lpPortName *uint16,
	dwOptions uint32,
	lpContext uintptr,
	wSizeOfContext uint16,
	lpSecurityAttributes LpsecurityAttributes,
	hPort *syscall.Handle) (int32, error) {
	r1, _, err := filterConnectCommunicationPort.Call(
		uintptr(unsafe.Pointer(lpPortName)),
		uintptr(dwOptions),
		uintptr(lpContext),
		uintptr(wSizeOfContext),
		uintptr(lpSecurityAttributes),
		uintptr(unsafe.Pointer(hPort)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterCreate API wrapper generated from prototype
HRESULT WINAPI FilterCreate(
	 LPCWSTR lpFilterName,
	 HFILTER *hFilter);
*/
func FilterCreate(lpFilterName *uint16,
	hFilter *syscall.Handle) (int32, error) {
	r1, _, err := filterCreate.Call(
		uintptr(unsafe.Pointer(lpFilterName)),
		uintptr(unsafe.Pointer(hFilter)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterDetach API wrapper generated from prototype
HRESULT WINAPI FilterDetach(
	 LPCWSTR lpFilterName,
	 LPCWSTR lpVolumeName,
	 LPCWSTR lpInstanceName);
*/
func FilterDetach(lpFilterName *uint16,
	lpVolumeName *uint16,
	lpInstanceName *uint16) (int32, error) {
	r1, _, err := filterDetach.Call(
		uintptr(unsafe.Pointer(lpFilterName)),
		uintptr(unsafe.Pointer(lpVolumeName)),
		uintptr(unsafe.Pointer(lpInstanceName)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterFindClose API wrapper generated from prototype
HRESULT WINAPI FilterFindClose(
	 HANDLE hFilterFind);
*/
func FilterFindClose(hFilterFind syscall.Handle) (int32, error) {
	r1, _, err := filterFindClose.Call(
		uintptr(hFilterFind))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterFindFirst API wrapper generated from prototype
HRESULT WINAPI FilterFindFirst(
	 FILTER_INFORMATION_CLASS dwInformationClass,
	 LPVOID lpBuffer,
	 DWORD dwBufferSize,
	 LPDWORD lpBytesReturned,
	 LPHANDLE lpFilterFind);
*/
func FilterFindFirst(dwInformationClass FilterInformationClass,
	lpBuffer uintptr,
	dwBufferSize uint32,
	lpBytesReturned *uint32,
	lpFilterFind *syscall.Handle) (int32, error) {
	r1, _, err := filterFindFirst.Call(
		uintptr(dwInformationClass),
		uintptr(lpBuffer),
		uintptr(dwBufferSize),
		uintptr(unsafe.Pointer(lpBytesReturned)),
		uintptr(lpFilterFind))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterFindNext API wrapper generated from prototype
HRESULT WINAPI FilterFindNext(
	 HANDLE hFilterFind,
	 FILTER_INFORMATION_CLASS dwInformationClass,
	 LPVOID lpBuffer,
	 DWORD dwBufferSize,
	 LPDWORD lpBytesReturned);
*/
func FilterFindNext(hFilterFind syscall.Handle,
	dwInformationClass FilterInformationClass,
	lpBuffer uintptr,
	dwBufferSize uint32,
	lpBytesReturned *uint32) (int32, error) {
	r1, _, err := filterFindNext.Call(
		uintptr(hFilterFind),
		uintptr(dwInformationClass),
		uintptr(lpBuffer),
		uintptr(dwBufferSize),
		uintptr(unsafe.Pointer(lpBytesReturned)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterGetDosName API wrapper generated from prototype
HRESULT WINAPI FilterGetDosName(
	 LPCWSTR lpVolumeName,
	 LPWSTR lpDosName,
	 DWORD dwDosNameBufferSize);
*/
func FilterGetDosName(lpVolumeName *uint16,
	lpDosName *uint16,
	dwDosNameBufferSize uint32) (int32, error) {
	r1, _, err := filterGetDosName.Call(
		uintptr(unsafe.Pointer(lpVolumeName)),
		uintptr(unsafe.Pointer(lpDosName)),
		uintptr(dwDosNameBufferSize))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterGetInformation API wrapper generated from prototype
HRESULT WINAPI FilterGetInformation(
	 HFILTER hFilter,
	 FILTER_INFORMATION_CLASS dwInformationClass,
	 LPVOID lpBuffer,
	 DWORD dwBufferSize,
	 LPDWORD lpBytesReturned);
*/
func FilterGetInformation(hFilter syscall.Handle,
	dwInformationClass FilterInformationClass,
	lpBuffer uintptr,
	dwBufferSize uint32,
	lpBytesReturned *uint32) (int32, error) {
	r1, _, err := filterGetInformation.Call(
		uintptr(hFilter),
		uintptr(dwInformationClass),
		uintptr(lpBuffer),
		uintptr(dwBufferSize),
		uintptr(unsafe.Pointer(lpBytesReturned)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterGetMessage API wrapper generated from prototype
HRESULT WINAPI FilterGetMessage(
	 HANDLE hPort,
	 PFILTER_MESSAGE_HEADER lpMessageBuffer,
	 DWORD dwMessageBufferSize,
	 LPOVERLAPPED lpOverlapped);
*/
func FilterGetMessage(hPort syscall.Handle,
	lpMessageBuffer *FilterMessageHeader,
	dwMessageBufferSize uint32,
	lpOverlapped LPOVERLAPPED) (int32, error) {
	r1, _, err := filterGetMessage.Call(
		uintptr(hPort),
		uintptr(unsafe.Pointer(lpMessageBuffer)),
		uintptr(dwMessageBufferSize),
		uintptr(lpOverlapped))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterInstanceClose API wrapper generated from prototype
HRESULT WINAPI FilterInstanceClose(
	 HFILTER_INSTANCE hInstance);
*/
func FilterInstanceClose(hInstance HfilterInstance) (int32, error) {
	r1, _, err := filterInstanceClose.Call(
		uintptr(hInstance))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterInstanceCreate API wrapper generated from prototype
HRESULT WINAPI FilterInstanceCreate(
	 LPCWSTR lpFilterName,
	 LPCWSTR lpVolumeName,
	 LPCWSTR lpInstanceName,
	 HFILTER_INSTANCE *hInstance);
*/
func FilterInstanceCreate(lpFilterName *uint16,
	lpVolumeName *uint16,
	lpInstanceName *uint16,
	hInstance *HfilterInstance) (int32, error) {
	r1, _, err := filterInstanceCreate.Call(
		uintptr(unsafe.Pointer(lpFilterName)),
		uintptr(unsafe.Pointer(lpVolumeName)),
		uintptr(unsafe.Pointer(lpInstanceName)),
		uintptr(unsafe.Pointer(hInstance)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterInstanceFindClose API wrapper generated from prototype
HRESULT WINAPI FilterInstanceFindClose(
	 HANDLE hFilterInstanceFind);
*/
func FilterInstanceFindClose(hFilterInstanceFind syscall.Handle) (int32, error) {
	r1, _, err := filterInstanceFindClose.Call(
		uintptr(hFilterInstanceFind))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterInstanceFindFirst API wrapper generated from prototype
HRESULT WINAPI FilterInstanceFindFirst(
	 LPCWSTR lpFilterName,
	 INSTANCE_INFORMATION_CLASS dwInformationClass,
	 LPVOID lpBuffer,
	 DWORD dwBufferSize,
	 LPDWORD lpBytesReturned,
	 LPHANDLE lpFilterInstanceFind);
*/
func FilterInstanceFindFirst(lpFilterName *uint16,
	dwInformationClass InstanceInformationClass,
	lpBuffer uintptr,
	dwBufferSize uint32,
	lpBytesReturned *uint32,
	lpFilterInstanceFind *syscall.Handle) (int32, error) {
	r1, _, err := filterInstanceFindFirst.Call(
		uintptr(unsafe.Pointer(lpFilterName)),
		uintptr(dwInformationClass),
		uintptr(lpBuffer),
		uintptr(dwBufferSize),
		uintptr(unsafe.Pointer(lpBytesReturned)),
		uintptr(lpFilterInstanceFind))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterInstanceFindNext API wrapper generated from prototype
HRESULT WINAPI FilterInstanceFindNext(
	 HANDLE hFilterInstanceFind,
	 INSTANCE_INFORMATION_CLASS dwInformationClass,
	 LPVOID lpBuffer,
	 DWORD dwBufferSize,
	 LPDWORD lpBytesReturned);
*/
func FilterInstanceFindNext(hFilterInstanceFind syscall.Handle,
	dwInformationClass InstanceInformationClass,
	lpBuffer uintptr,
	dwBufferSize uint32,
	lpBytesReturned *uint32) (int32, error) {
	r1, _, err := filterInstanceFindNext.Call(
		uintptr(hFilterInstanceFind),
		uintptr(dwInformationClass),
		uintptr(lpBuffer),
		uintptr(dwBufferSize),
		uintptr(unsafe.Pointer(lpBytesReturned)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterInstanceGetInformation API wrapper generated from prototype
HRESULT WINAPI FilterInstanceGetInformation(
	 HFILTER_INSTANCE hInstance,
	 INSTANCE_INFORMATION_CLASS dwInformationClass,
	 LPVOID lpBuffer,
	 DWORD dwBufferSize,
	 LPDWORD lpBytesReturned);
*/
func FilterInstanceGetInformation(hInstance HfilterInstance,
	dwInformationClass InstanceInformationClass,
	lpBuffer uintptr,
	dwBufferSize uint32,
	lpBytesReturned *uint32) (int32, error) {
	r1, _, err := filterInstanceGetInformation.Call(
		uintptr(hInstance),
		uintptr(dwInformationClass),
		uintptr(lpBuffer),
		uintptr(dwBufferSize),
		uintptr(unsafe.Pointer(lpBytesReturned)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterLoad API wrapper generated from prototype
HRESULT WINAPI FilterLoad(
	 LPCWSTR lpFilterName);
*/
func FilterLoad(lpFilterName *uint16) (int32, error) {
	r1, _, err := filterLoad.Call(
		uintptr(unsafe.Pointer(lpFilterName)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterReplyMessage API wrapper generated from prototype
HRESULT WINAPI FilterReplyMessage(
	 HANDLE hPort,
	PFILTER_REPLY_HEADER lpReplyBuffer,
	DWORD dwReplyBufferSize);
*/
func FilterReplyMessage(hPort syscall.Handle,
	lpReplyBuffer *FilterReplyHeader,
	dwReplyBufferSize uint32) (int32, error) {
	r1, _, err := filterReplyMessage.Call(
		uintptr(hPort),
		uintptr(unsafe.Pointer(lpReplyBuffer)),
		uintptr(dwReplyBufferSize))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterSendMessage API wrapper generated from prototype
HRESULT WINAPI FilterSendMessage(
	 HANDLE hPort,
	 LPVOID lpInBuffer,
	 DWORD dwInBufferSize,
	 LPVOID lpOutBuffer,
	 DWORD dwOutBufferSize,
	 LPDWORD lpBytesReturned);
*/
func FilterSendMessage(hPort syscall.Handle,
	lpInBuffer uintptr,
	dwInBufferSize uint32,
	lpOutBuffer uintptr,
	dwOutBufferSize uint32,
	lpBytesReturned *uint32) (int32, error) {
	r1, _, err := filterSendMessage.Call(
		uintptr(hPort),
		uintptr(lpInBuffer),
		uintptr(dwInBufferSize),
		uintptr(lpOutBuffer),
		uintptr(dwOutBufferSize),
		uintptr(unsafe.Pointer(lpBytesReturned)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterUnload API wrapper generated from prototype
HRESULT WINAPI FilterUnload(
	 LPCWSTR lpFilterName);
*/
func FilterUnload(lpFilterName *uint16) (int32, error) {
	r1, _, err := filterUnload.Call(
		uintptr(unsafe.Pointer(lpFilterName)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterVolumeFindClose API wrapper generated from prototype
HRESULT WINAPI FilterVolumeFindClose(
	 HANDLE hVolumeFind);
*/
func FilterVolumeFindClose(hVolumeFind syscall.Handle) (int32, error) {
	r1, _, err := filterVolumeFindClose.Call(
		uintptr(hVolumeFind))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterVolumeFindFirst API wrapper generated from prototype
HRESULT WINAPI FilterVolumeFindFirst(
	 FILTER_VOLUME_INFORMATION_CLASS dwInformationClass,
	 LPVOID lpBuffer,
	 DWORD dwBufferSize,
	 LPDWORD lpBytesReturned,
	 PHANDLE lpVolumeFind);
*/
func FilterVolumeFindFirst(dwInformationClass FilterVolumeInformationClass,
	lpBuffer uintptr,
	dwBufferSize uint32,
	lpBytesReturned *uint32,
	lpVolumeFind *syscall.Handle) (int32, error) {
	r1, _, err := filterVolumeFindFirst.Call(
		uintptr(dwInformationClass),
		uintptr(lpBuffer),
		uintptr(dwBufferSize),
		uintptr(unsafe.Pointer(lpBytesReturned)),
		uintptr(unsafe.Pointer(lpVolumeFind)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterVolumeFindNext API wrapper generated from prototype
HRESULT WINAPI FilterVolumeFindNext(
	 HANDLE hVolumeFind,
	 FILTER_VOLUME_INFORMATION_CLASS dwInformationClass,
	 LPVOID lpBuffer,
	 DWORD dwBufferSize,
	 LPDWORD lpBytesReturned);
*/
func FilterVolumeFindNext(hVolumeFind syscall.Handle,
	dwInformationClass FilterVolumeInformationClass,
	lpBuffer uintptr,
	dwBufferSize uint32,
	lpBytesReturned *uint32) (int32, error) {
	r1, _, err := filterVolumeFindNext.Call(
		uintptr(hVolumeFind),
		uintptr(dwInformationClass),
		uintptr(lpBuffer),
		uintptr(dwBufferSize),
		uintptr(unsafe.Pointer(lpBytesReturned)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterVolumeInstanceFindClose API wrapper generated from prototype
HRESULT WINAPI FilterVolumeInstanceFindClose(
	 HANDLE hVolumeInstanceFind);
*/
func FilterVolumeInstanceFindClose(hVolumeInstanceFind syscall.Handle) (int32, error) {
	r1, _, err := filterVolumeInstanceFindClose.Call(
		uintptr(hVolumeInstanceFind))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterVolumeInstanceFindFirst API wrapper generated from prototype
HRESULT WINAPI FilterVolumeInstanceFindFirst(
	 LPCWSTR lpVolumeName,
	 INSTANCE_INFORMATION_CLASS dwInformationClass,
	 LPVOID lpBuffer,
	 DWORD dwBufferSize,
	 LPDWORD lpBytesReturned,
	 LPHANDLE lpVolumeInstanceFind);
*/
func FilterVolumeInstanceFindFirst(lpVolumeName *uint16,
	dwInformationClass InstanceInformationClass,
	lpBuffer uintptr,
	dwBufferSize uint32,
	lpBytesReturned *uint32,
	lpVolumeInstanceFind syscall.Handle) (int32, error) {
	r1, _, err := filterVolumeInstanceFindFirst.Call(
		uintptr(unsafe.Pointer(lpVolumeName)),
		uintptr(dwInformationClass),
		uintptr(lpBuffer),
		uintptr(dwBufferSize),
		uintptr(unsafe.Pointer(lpBytesReturned)),
		uintptr(lpVolumeInstanceFind))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}

/*
FilterVolumeInstanceFindNext API wrapper generated from prototype
HRESULT WINAPI FilterVolumeInstanceFindNext(
	 HANDLE hVolumeInstanceFind,
	 INSTANCE_INFORMATION_CLASS dwInformationClass,
	 LPVOID lpBuffer,
	 DWORD dwBufferSize,
	 LPDWORD lpBytesReturned);
*/
func FilterVolumeInstanceFindNext(hVolumeInstanceFind syscall.Handle,
	dwInformationClass InstanceInformationClass,
	lpBuffer uintptr,
	dwBufferSize uint32,
	lpBytesReturned *uint32) (int32, error) {
	r1, _, err := filterVolumeInstanceFindNext.Call(
		uintptr(hVolumeInstanceFind),
		uintptr(dwInformationClass),
		uintptr(lpBuffer),
		uintptr(dwBufferSize),
		uintptr(unsafe.Pointer(lpBytesReturned)))
	if err.(syscall.Errno) == 0 {
		return int32(r1), nil
	}
	return int32(r1), err
}
