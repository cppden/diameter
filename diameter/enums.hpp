#pragma once
/**
@file
RFC6733/3588 DIAMETER protocol definition in med (https://github.com/cppden/med)

@copyright Denis Priyomov 2018
Distributed under the MIT License
(See accompanying file LICENSE or visit https://github.com/cppden/med)
*/

#include <cstdint>

namespace diameter {

enum class RESULT : uint32_t
{
	//Informational
	MULTI_ROUND_AUTH             = 1001,
	//Success
	SUCCESS                      = 2001,
	LIMITED_SUCCESS              = 2002,
	//Protocol Errors
	COMMAND_UNSUPPORTED          = 3001,
	UNABLE_TO_DELIVER            = 3002,
	REALM_NOT_SERVED             = 3003,
	TOO_BUSY                     = 3004,
	LOOP_DETECTED                = 3005,
	REDIRECT_INDICATION          = 3006,
	APPLICATION_UNSUPPORTED      = 3007,
	INVALID_HDR_BITS             = 3008,
	INVALID_AVP_BITS             = 3009,
	UNKNOWN_PEER                 = 3010,
	//Transient Failures
	AUTHENTICATION_REJECTED      = 4001,
	OUT_OF_SPACE                 = 4002,
	ELECTION_LOST                = 4003,
	//Permanent Failures
	AVP_UNSUPPORTED              = 5001,
	UNKNOWN_SESSION_ID           = 5002,
	AUTHORIZATION_REJECTED       = 5003,
	INVALID_AVP_VALUE            = 5004,
	MISSING_AVP                  = 5005,
	RESOURCES_EXCEEDED           = 5006,
	CONTRADICTING_AVPS           = 5007,
	AVP_NOT_ALLOWED              = 5008,
	AVP_OCCURS_TOO_MANY_TIMES    = 5009,
	NO_COMMON_APPLICATION        = 5010,
	UNSUPPORTED_VERSION          = 5011,
	UNABLE_TO_COMPLY             = 5012,
	INVALID_BIT_IN_HEADER        = 5013,
	INVALID_AVP_LENGTH           = 5014,
	INVALID_MESSAGE_LENGTH       = 5015,
	INVALID_AVP_BIT_COMBO        = 5016,
	NO_COMMON_SECURITY           = 5017,
	DUPLICATED_AF_SESSION        = 5064,
	IP_CAN_SESSION_NOT_AVAILABLE = 5065,
	//General Failure
	ENCODE_FAILURE               = 10000,
	ENCODE_SUCCESS               = 10001,
};

enum class EXPERIMENTAL_RESULT : uint32_t
{
	//success
	FIRST_REGISTRATION                             = 2001,
	SUBSEQUENT_REGISTRATION                        = 2002,
	UNREGISTERED_SERVICE                           = 2003,
	SUCCESS_SERVER_NAME_NOT_STORED                 = 2004,
	//permanent failures
	AUTHENTICATION_DATA_UNAVAILABLE                = 4181,
	ERROR_CAMEL_SUBSCRIPTION_PRESENT               = 4182,
	ERROR_USER_UNKNOWN                             = 5001,
	ERROR_IDENTITIES_DONT_MATCH                    = 5002,
	ERROR_IDENTITY_NOT_REGISTERED                  = 5003,
	ERROR_ROAMING_NOT_ALLOWED                      = 5004,
	ERROR_IDENTITY_ALREADY_REGISTERED              = 5005,
	ERROR_AUTH_SCHEME_NOT_SUPPORTED                = 5006,
	ERROR_IN_ASSIGNMENT_TYPE                       = 5007,
	ERROR_TOO_MUCH_DATA                            = 5008,
	ERROR_NOT_SUPPORTED_USER_DATA                  = 5009,
	ERROR_FEATURE_UNSUPPORTED                      = 5011,
	ERROR_SERVING_NODE_FEATURE_UNSUPPORTED         = 5012,
	ERROR_UNKNOWN_EPS_SUBSCRIPTION                 = 5420,
	ERROR_RAT_NOT_ALLOWED                          = 5421,
	ERROR_EQUIPMENT_UNKNOWN                        = 5422,
	ERROR_UNKNOWN_SERVING_NODE                     = 5423,
	//Rx specific
	ERROR_INVALID_SERVICE_INFORMATION              = 5061,
	ERROR_FILTER_RESTRICTIONS                      = 5062,
	ERROR_REQUESTED_SERVICE_NOT_AUTHORIZED         = 5063,
	ERROR_DUPLICATED_AF_SESSION                    = 5064,
	ERROR_IPCAN_SESSION_NOT_AVAILABLE              = 5065,
	ERROR_UNAUTHORIZED_NON_EMERGENCY_SESSION       = 5066,
	ERROR_UNAUTHORIZED_SPONSORED_DATA_CONNECTIVITY = 5067,
	ERROR_TEMPORARY_NETWORK_FAILURE                = 5068,
};

enum class APPLICATION : uint32_t
{
	NONE       = 0,
	CXDX       = 16777216, //29.228 and 29.229
	SHPH       = 16777217, //29.328 and 29.329
	RE         = 16777218, //32.296
	WX         = 16777219, //29.234
	ZN         = 16777220, //29.109
	ZH         = 16777221, //29.109
	GQ         = 16777222, //29.209
	GMB        = 16777223, //29.061
	GX_OVER_GY = 16777225, //29.210
	MM10       = 16777226, //29.140
	PR         = 16777230, //29.234
	RX         = 16777236, //29.214
	GX         = 16777238, //29.212
	STA        = 16777250, //29.273
	S6A        = 16777251, //29.272
	S13        = 16777252, //29.272
	SLG        = 16777255, //29.172
	SWM        = 16777264, //29.273
	SWX        = 16777265, //29.273
	GXX        = 16777266, //29.212
	S9         = 16777267, //29.215
	ZPN        = 16777268, //29.109
	S6B        = 16777272, //29.273
	SLH        = 16777291, //29.173
	SGMB       = 16777292, //29.061
	SY         = 16777302, //29.219
	SD         = 16777303, //29.212
	S7A        = 16777308, //29.272
	TSP        = 16777309, //29.368
	S6M        = 16777310, //29.336
	T4         = 16777311, //29.337
	S6C        = 16777312, //29.338
	SGD        = 16777313, //29.338
	S15        = 16777318, //29.212
	S9A        = 16777319, //29.215
	S9A_STAR   = 16777320, //29.215
	MB2_C      = 16777335, //29.468
	PC4A       = 16777336, //29.344
	PC2        = 16777337, //29.343
	PC6PC7     = 16777340, //29.345
};

}	//end: namespace diameter
