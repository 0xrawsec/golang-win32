// +build windows

package fltlib

import "syscall"

var (
	fltlib                         = syscall.NewLazyDLL("fltlib.dll")
	filterAttach                   = fltlib.NewProc("FilterAttach")
	filterAttachAtAltitude         = fltlib.NewProc("FilterAttachAtAltitude")
	filterClose                    = fltlib.NewProc("FilterClose")
	filterConnectCommunicationPort = fltlib.NewProc("FilterConnectCommunicationPort")
	filterCreate                   = fltlib.NewProc("FilterCreate")
	filterDetach                   = fltlib.NewProc("FilterDetach")
	filterFindClose                = fltlib.NewProc("FilterFindClose")
	filterFindFirst                = fltlib.NewProc("FilterFindFirst")
	filterFindNext                 = fltlib.NewProc("FilterFindNext")
	filterGetDosName               = fltlib.NewProc("FilterGetDosName")
	filterGetInformation           = fltlib.NewProc("FilterGetInformation")
	filterGetMessage               = fltlib.NewProc("FilterGetMessage")
	filterInstanceClose            = fltlib.NewProc("FilterInstanceClose")
	filterInstanceCreate           = fltlib.NewProc("FilterInstanceCreate")
	filterInstanceFindClose        = fltlib.NewProc("FilterInstanceFindClose")
	filterInstanceFindFirst        = fltlib.NewProc("FilterInstanceFindFirst")
	filterInstanceFindNext         = fltlib.NewProc("FilterInstanceFindNext")
	filterInstanceGetInformation   = fltlib.NewProc("FilterInstanceGetInformation")
	filterLoad                     = fltlib.NewProc("FilterLoad")
	filterReplyMessage             = fltlib.NewProc("FilterReplyMessage")
	filterSendMessage              = fltlib.NewProc("FilterSendMessage")
	filterUnload                   = fltlib.NewProc("FilterUnload")
	filterVolumeClose              = fltlib.NewProc("FilterVolumeClose")
	filterVolumeFindClose          = fltlib.NewProc("FilterVolumeFindClose")
	filterVolumeFindFirst          = fltlib.NewProc("FilterVolumeFindFirst")
	filterVolumeFindNext           = fltlib.NewProc("FilterVolumeFindNext")
	filterVolumeInstanceFindClose  = fltlib.NewProc("FilterVolumeInstanceFindClose")
	filterVolumeInstanceFindFirst  = fltlib.NewProc("FilterVolumeInstanceFindFirst")
	filterVolumeInstanceFindNext   = fltlib.NewProc("FilterVolumeInstanceFindNext")
)
