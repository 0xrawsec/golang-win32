package wevtapi

import (
	"fmt"

	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-win32/win32"
)

// Should be an enum  _EVT_SUBSCRIBE_NOTIFY_ACTION
type EVT_SUBSCRIBE_NOTIFY_ACTION int

const (
	// EVT_SUBSCRIBE_NOTIFY_ACTION enum: https://msdn.microsoft.com/en-us/library/windows/desktop/aa385596(v=vs.85).aspx
	//typedef enum _EVT_SUBSCRIBE_NOTIFY_ACTION {
	EvtSubscribeActionError   = 0
	EvtSubscribeActionDeliver = 1
	//} EVT_SUBSCRIBE_NOTIFY_ACTION;

	// EVT_RENDER_FLAGS enum: https://msdn.microsoft.com/en-us/library/windows/desktop/aa385563(v=vs.85).aspx
	//typedef enum _EVT_RENDER_FLAGS {
	EvtRenderEventValues = 0
	EvtRenderEventXml    = 1
	EvtRenderBookmark    = 2
	//} EVT_RENDER_FLAGS;

	// EVT_SUBSCRIBE_FLAGS enum: https://msdn.microsoft.com/en-us/library/windows/desktop/aa385588(v=vs.85).aspx
	//typedef enum _EVT_SUBSCRIBE_FLAGS {
	EvtSubscribeToFutureEvents      = 1
	EvtSubscribeStartAtOldestRecord = 2
	EvtSubscribeStartAfterBookmark  = 3
	EvtSubscribeOriginMask          = 0x3
	EvtSubscribeTolerateQueryErrors = 0x1000
	EvtSubscribeStrict              = 0x10000
	//} EVT_SUBSCRIBE_FLAGS;
)

const (
	ERROR_EVT_INVALID_CHANNEL_PATH                          = 15000
	ERROR_EVT_INVALID_QUERY                                 = 15001
	ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND                  = 15002
	ERROR_EVT_EVENT_TEMPLATE_NOT_FOUND                      = 15003
	ERROR_EVT_INVALID_PUBLISHER_NAME                        = 15004
	ERROR_EVT_INVALID_EVENT_DATA                            = 15005
	ERROR_EVT_CHANNEL_NOT_FOUND                             = 15007
	ERROR_EVT_MALFORMED_XML_TEXT                            = 15008
	ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL                = 15009
	ERROR_EVT_CONFIGURATION_ERROR                           = 15010
	ERROR_EVT_QUERY_RESULT_STALE                            = 15011
	ERROR_EVT_QUERY_RESULT_INVALID_POSITION                 = 15012
	ERROR_EVT_NON_VALIDATING_MSXML                          = 15013
	ERROR_EVT_FILTER_ALREADYSCOPED                          = 15014
	ERROR_EVT_FILTER_NOTELTSET                              = 15015
	ERROR_EVT_FILTER_INVARG                                 = 15016
	ERROR_EVT_FILTER_INVTEST                                = 15017
	ERROR_EVT_FILTER_INVTYPE                                = 15018
	ERROR_EVT_FILTER_PARSEERR                               = 15019
	ERROR_EVT_FILTER_UNSUPPORTEDOP                          = 15020
	ERROR_EVT_FILTER_UNEXPECTEDTOKEN                        = 15021
	ERROR_EVT_INVALID_OPERATION_OVER_ENABLED_DIRECT_CHANNEL = 15022
	ERROR_EVT_INVALID_CHANNEL_PROPERTY_VALUE                = 15023
	ERROR_EVT_INVALID_PUBLISHER_PROPERTY_VALUE              = 15024
	ERROR_EVT_CHANNEL_CANNOT_ACTIVATE                       = 15025
	ERROR_EVT_FILTER_TOO_COMPLEX                            = 15026
	ERROR_EVT_MESSAGE_NOT_FOUND                             = 15027
	ERROR_EVT_MESSAGE_ID_NOT_FOUND                          = 15028
	ERROR_EVT_UNRESOLVED_VALUE_INSERT                       = 15029
	ERROR_EVT_UNRESOLVED_PARAMETER_INSERT                   = 15030
	ERROR_EVT_MAX_INSERTS_REACHED                           = 15031
	ERROR_EVT_EVENT_DEFINITION_NOT_FOUND                    = 15032
	ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND                      = 15033
	ERROR_EVT_VERSION_TOO_OLD                               = 15034
	ERROR_EVT_VERSION_TOO_NEW                               = 15035
	ERROR_EVT_CANNOT_OPEN_CHANNEL_OF_QUERY                  = 15036
	ERROR_EVT_PUBLISHER_DISABLED                            = 15037
	ERROR_EVT_FILTER_OUT_OF_RANGE                           = 15038
)

type EVT_SUBSCRIBE_CALLBACK func(Action EVT_SUBSCRIBE_NOTIFY_ACTION, UserContext win32.PVOID, Event EVT_HANDLE) uintptr
type EVT_HANDLE win32.HANDLE

func TestCallback(Action EVT_SUBSCRIBE_NOTIFY_ACTION, UserContext win32.PVOID, Event EVT_HANDLE) uintptr {
	log.Info("In TestCallback")
	fmt.Printf("Super it works\n")
	return uintptr(0)
}
