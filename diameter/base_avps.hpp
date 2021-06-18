#pragma once
/**
@file
RFC6733/3588 DIAMETER protocol definition in med (https://github.com/cppden/med)

@copyright Denis Priyomov 2018
Distributed under the MIT License
(See accompanying file LICENSE or visit https://github.com/cppden/med)
*/

#include <chrono>
#include <arpa/inet.h>

#include "med/octet_string.hpp"
#include "med/set.hpp"
#include "avp.hpp"
#include "enums.hpp"

namespace diameter {

/*
The Address format is derived from the OctetString AVP Base Format.
It is a discriminated union, representing, for example a 32-bit (IPv4) [IPV4] or 128-bit (IPv6) [IPV6] address,
most significant octet first.  The first two octets of the Address AVP represents the AddressType, which contains
an Address Family defined in [IANAADFAM].
*/
using address_t = med::octet_string<med::octets_var_intern<18>, med::min<6>>;
struct address : address_t
{
	enum iana_addr_type : uint16_t
	{
		IPV4 = 1,
		IPV6 = 2,
	};

	using address_t::set;

	void set(size_t ip_size, void const* ip_data)
	{
		//IPv4: 1st two bytes is 00 01 followed by 4 bytes of the IPV4 Address.
		//IPv6: 1st two bytes is 00 02 followed by 16 bytes of the IPV6 Address.
		if (ip_size == 4)
		{
			resize(6);
			data()[0] = 0;
			data()[1] = IPV4;

			std::memcpy(data()+2, ip_data, 4);
		}
		else if (ip_size == 16)
		{
			resize(18);
			data()[0] = 0;
			data()[1] = IPV6;

			std::memcpy(data() + 2, ip_data, 16);
		}
	}

	static constexpr char const* name() { return "Address"; }

	template <std::size_t N>
	void print(char (&sz)[N]) const
	{
		uint8_t const* p = this->data() + 2;
		if (6 == this->size())
		{
			snprintf(sz, sizeof(sz), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
		}
		else
		{
			struct in6_addr in_addr;
			std::memcpy(in_addr.s6_addr, p, sizeof(in_addr.s6_addr));
			inet_ntop(AF_INET6, in_addr.s6_addr, sz, sizeof(sz)-1);
		}
	}

};

/*
The Time format is derived from the OctetString AVP Base Format.
The string MUST contain four octets, in the same format as the first four bytes are in the NTP timestamp format.
This represents the number of seconds since 0h on 1 January 1900 with respect to the Coordinated Universal Time (UTC).
*/
struct time : med::octet_string<med::octets_fix_intern<4>>
{
	static constexpr char const* name() { return "Time"; }
};

struct integer32 :  med::value<uint32_t>
{
	static constexpr char const* name() { return "Integer32"; }
};

struct integer64 :  med::value<uint64_t>
{
	static constexpr char const* name() { return "Integer64"; }
};

struct unsigned32 : med::value<uint32_t>
{
	static constexpr char const* name() { return "Unsigned32"; }
};

struct unsigned64 : med::value<uint64_t>
{
	static constexpr char const* name() { return "Unsigned64"; }
};

template <typename ENUM>
struct enumerated : unsigned32
{
	//using value_type = ENUM;
	static_assert(std::is_enum_v<ENUM>, "ENUM EXPECTED");
	static_assert(sizeof(std::underlying_type_t<ENUM>) <= sizeof(value_type), "OVERSIZED ENUM");
	ENUM get() const                    { return static_cast<ENUM>(unsigned32::get()); }
	auto set(ENUM v)                    { return unsigned32::set(static_cast<value_type>(v)); }

	static constexpr char const* name() { return "Enumerated"; }
};

/*
                                                      +----------+
                                                      | AVP Flag |
                                                      |  rules   |
                                                      |----+-----|
                              AVP  Section            |    |MUST |
Attribute Name                Code Defined  Data Type |MUST| NOT |
------------------------------------------------------|----+-----|
Acct-Interim-Interval          85  9.8.2   Unsigned32 | M  |  V  |
Accounting-Realtime-Required  483  9.8.7   Enumerated | M  |  V  |
Acct-Multi-Session-Id          50  9.8.5   UTF8String | M  |  V  |
Accounting-Record-Number      485  9.8.3   Unsigned32 | M  |  V  |
Accounting-Record-Type        480  9.8.1   Enumerated | M  |  V  |
Acct-Session-Id                44  9.8.4   OctetString| M  |  V  |
Accounting-Sub-Session-Id     287  9.8.6   Unsigned64 | M  |  V  |
Acct-Application-Id           259  6.9     Unsigned32 | M  |  V  |
Auth-Application-Id           258  6.8     Unsigned32 | M  |  V  |
Auth-Request-Type             274  8.7     Enumerated | M  |  V  |
Authorization-Lifetime        291  8.9     Unsigned32 | M  |  V  |
Auth-Grace-Period             276  8.10    Unsigned32 | M  |  V  |
Auth-Session-State            277  8.11    Enumerated | M  |  V  |
Re-Auth-Request-Type          285  8.12    Enumerated | M  |  V  |
Class                          25  8.20    OctetString| M  |  V  |
Destination-Host              293  6.5     DiamIdent  | M  |  V  |
Destination-Realm             283  6.6     DiamIdent  | M  |  V  |
Disconnect-Cause              273  5.4.3   Enumerated | M  |  V  |
Error-Message                 281  7.3     UTF8String |    | V,M |
Error-Reporting-Host          294  7.4     DiamIdent  |    | V,M |
Event-Timestamp                55  8.21    Time       | M  |  V  |
Experimental-Result           297  7.6     Grouped    | M  |  V  |
Experimental-Result-Code      298  7.7     Unsigned32 | M  |  V  |
Failed-AVP                    279  7.5     Grouped    | M  |  V  |
Firmware-Revision             267  5.3.4   Unsigned32 |    | V,M |
Host-IP-Address               257  5.3.5   Address    | M  |  V  |
Inband-Security-Id            299  6.10    Unsigned32 | M  |  V  |
Multi-Round-Time-Out          272  8.19    Unsigned32 | M  |  V  |
Origin-Host                   264  6.3     DiamIdent  | M  |  V  |
Origin-Realm                  296  6.4     DiamIdent  | M  |  V  |
Origin-State-Id               278  8.16    Unsigned32 | M  |  V  |
Product-Name                  269  5.3.7   UTF8String |    | V,M |
Proxy-Host                    280  6.7.3   DiamIdent  | M  |  V  |
Proxy-Info                    284  6.7.2   Grouped    | M  |  V  |
Proxy-State                    33  6.7.4   OctetString| M  |  V  |
Redirect-Host                 292  6.12    DiamURI    | M  |  V  |
Redirect-Host-Usage           261  6.13    Enumerated | M  |  V  |
Redirect-Max-Cache-Time       262  6.14    Unsigned32 | M  |  V  |
Result-Code                   268  7.1     Unsigned32 | M  |  V  |
Route-Record                  282  6.7.1   DiamIdent  | M  |  V  |
Session-Id                    263  8.8     UTF8String | M  |  V  |
Session-Timeout                27  8.13    Unsigned32 | M  |  V  |
Session-Binding               270  8.17    Unsigned32 | M  |  V  |
Session-Server-Failover       271  8.18    Enumerated | M  |  V  |
Supported-Vendor-Id           265  5.3.6   Unsigned32 | M  |  V  |
Termination-Cause             295  8.15    Enumerated | M  |  V  |
User-Name                       1  8.14    UTF8String | M  |  V  |
Vendor-Id                     266  5.3.3   Unsigned32 | M  |  V  |
Vendor-Specific-Application-Id 260  6.11   Grouped    | M  |  V  |
*/


struct user_name : avp<med::ascii_string<>, 1, avp_flags::M>
{
	static constexpr char const* name() { return "User-Name"; }
};

struct Class : avp<med::ascii_string<>, 25, avp_flags::M>
{
	static constexpr char const* name() { return "Class"; }
};

struct proxy_state : avp<med::octet_string<>, 33, avp_flags::M>
{
	static constexpr char const* name() { return "Proxy-State"; }
};

struct host_ip_address : avp<address, 257, avp_flags::M>
{
	static constexpr char const* name() { return "Host-IP-Address"; }
};

constexpr std::size_t MAX_SESSION_ID_LEN = 512;

struct session_id : avp<med::ascii_string<med::octets_var_intern<MAX_SESSION_ID_LEN>>, 263, avp_flags::M>
{
	void set(char const* fqdn, char const* optional = nullptr)
	{
		static uint32_t loBits = 0;

		if (fqdn && fqdn[0])
		{
			uint32_t const hiBits = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			char* out = (char*)body().emplace(MAX_SESSION_ID_LEN);
			auto const len = (optional && optional[0])
					? std::snprintf(out, MAX_SESSION_ID_LEN, "%s;%u;%u;%s", fqdn, hiBits, loBits, optional)
					: std::snprintf(out, MAX_SESSION_ID_LEN, "%s;%u;%u", fqdn, hiBits, loBits);
			if (len > 0)
			{
				++loBits;
				body().resize(std::size_t(len) < MAX_SESSION_ID_LEN ? std::size_t(len) : std::strlen(out));
			}
			else //error but how?
			{
				body().clear();
			}
		}
	}

	static constexpr char const* name() { return "Session-Id"; }
};

struct origin_host : avp<med::ascii_string<>, 264, avp_flags::M>
{
	static constexpr char const* name() { return "Origin-Host"; }
};

struct product_name : avp<med::ascii_string<>, 269>
{
	static constexpr char const* name() { return "Product-Name"; }
};

struct proxy_host : avp<med::ascii_string<>, 280, avp_flags::M>
{
	static constexpr char const* name() { return "Proxy-Host"; }
};

struct error_message : avp<med::ascii_string<>, 281>
{
	static constexpr char const* name() { return "Error-Message"; }
};

struct route_record: avp<med::ascii_string<>, 282, avp_flags::M>
{
	static constexpr char const* name() { return "Route-Record"; }
};

struct destination_realm : avp<med::ascii_string<>, 283, avp_flags::M>
{
	static constexpr char const* name() { return "Destination-Realm"; }
};

struct redirect_host : avp<med::ascii_string<>, 292, avp_flags::M>
{
	static constexpr char const* name() { return "Redirect-Host"; }
};

struct destination_host : avp<med::ascii_string<>, 293, avp_flags::M>
{
	static constexpr char const* name() { return "Destination-Host"; }
};

struct error_reporting_host : avp<med::ascii_string<>, 294>
{
	static constexpr char const* name() { return "Error-Reporting-Host"; }
};
struct event_timestamp : avp<time, 55, avp_flags::M>
{
	static constexpr char const* name() { return "Event-Timestamp"; }
};

struct origin_realm : avp<med::ascii_string<>, 296, avp_flags::M>
{
	static constexpr char const* name() { return "Origin-Realm"; }
};

enum class REDIRECT_HOST_USAGE : uint32_t
{
	DONT_CACHE            = 0,
	ALL_SESSION           = 1,
	ALL_REALM             = 2,
	REALM_AND_APPLICATION = 3,
	ALL_APPLICATION       = 4,
	ALL_HOST              = 5,
	ALL_USER              = 6,
};

struct redirect_host_usage : avp<enumerated<REDIRECT_HOST_USAGE>, 261, avp_flags::M>
{
	static constexpr char const* name() { return "Redirect-Host-Usage"; }
};

struct redirect_max_cache_time : avp<unsigned32, 262, avp_flags::M>
{
	static constexpr char const* name() { return "Redirect-Max-Cache-Time"; }
};

struct vendor_id : avp<enumerated<VENDOR>, 266, avp_flags::M>
{
	static constexpr char const* name() { return "Vendor-Id"; }
};

struct result_code : avp<enumerated<RESULT>, 268, avp_flags::M>
{
	bool is_accepted() const            { return RESULT::SUCCESS == body().get() || RESULT::LIMITED_SUCCESS == body().get(); }
	static constexpr char const* name() { return "Result-Code"; }
};

enum class DISCONNECT_CAUSE : uint32_t
{
	REBOOTING                  = 0,
	BUSY                       = 1,
	DO_NOT_WANT_TO_TALK_TO_YOU = 2,
};

struct disconnect_cause : avp<enumerated<DISCONNECT_CAUSE>, 273, avp_flags::M>
{
	static constexpr char const* name() { return "Disconnect-Cause"; }
};

struct origin_state_id : avp<unsigned32, 278, avp_flags::M>
{
	static constexpr char const* name() { return "Origin-State-Id"; }
};

struct supported_vendor_id : avp<enumerated<VENDOR>, 265, avp_flags::M>
{
	static constexpr char const* name() { return "Supported-Vendor-Id"; }
};

struct auth_application_id : avp<enumerated<APPLICATION>, 258, avp_flags::M>
{
	static constexpr char const* name() { return "Auth-Application-Id"; }
};

struct acct_application_id : avp<enumerated<APPLICATION>, 259, avp_flags::M>
{
	static constexpr char const* name() { return "Acct-Application-Id"; }
};

enum class ACCT_RECORD_TYPE : uint32_t
{
	EVENT_RECORD   = 1,
	START_RECORD   = 2,
	INTERIM_RECORD = 3,
	STOP_RECORD    = 4
};
struct acct_record_type : avp<enumerated<ACCT_RECORD_TYPE>, 480, avp_flags::M>
{
	static constexpr char const* name() { return "Acct-Record-Type"; }
};
struct acct_interim_interval : avp<unsigned32, 85, avp_flags::M>
{
	static constexpr char const* name() { return "Acct-Interim-Interval"; }
};
struct acct_record_number : avp<unsigned32, 485, avp_flags::M>
{
	static constexpr char const* name() { return "Acct-Record-Number"; }
};
struct acct_sub_session_id : avp<unsigned64, 287, avp_flags::M>
{
	static constexpr char const* name() { return "Acct-Sub-Session-Id"; }
};
struct acct_session_id : avp<med::octet_string<>, 44, avp_flags::M>
{
	static constexpr char const* name() { return "Acct-Session-Id"; }
};
struct acct_multi_session_id : avp<med::ascii_string<>, 50>
{
	static constexpr char const* name() { return "Acct-Multi-Session-Id"; }
};
enum class ACCT_REALTIME_REQUIRED : uint32_t
{
	DELIVER_AND_GRANT = 1,
	GRANT_AND_STORE   = 2,
	GRANT_AND_LOSE    = 3,
};
struct acct_realtime_required : avp<enumerated<ACCT_REALTIME_REQUIRED>, 483, avp_flags::M>
{
	static constexpr char const* name() { return "Acct-Realtime-Required"; }
};


struct firmware_revision : avp<unsigned32, 267>
{
	static constexpr char const* name() { return "Firmware-Revision"; }
};

enum class STATE : uint32_t
{
	MAINTAINED     = 0,
	NOT_MAINTAINED = 1,
};
struct auth_session_state : avp<enumerated<STATE>, 277, avp_flags::M>
{
	static constexpr char const* name() { return "Auth-Session-State"; }
};

enum class REAUTH : uint32_t
{
	AUTHORIZE_ONLY          = 0,
	AUTHORIZE_AUTHENTICATE  = 1,
};
struct re_auth_request_type : avp<enumerated<REAUTH>, 285, avp_flags::M>
{
	static constexpr char const* name() { return "Re-Auth-Request-Type"; }
};

enum class TERMINATION_CAUSE : uint32_t
{
	LOGOUT               = 1,
	SERVICE_NOT_PROVIDED = 2,
	BAD_ANSWER           = 3,
	ADMINISTRATIVE       = 4,
	LINK_BROKEN          = 5,
	AUTH_EXPIRED         = 6,
	USER_MOVED           = 7,
	SESSION_TIMEOUT      = 8,
};
struct termination_cause : avp<enumerated<TERMINATION_CAUSE>, 295, avp_flags::M>
{
	static constexpr char const* name() { return "Termination-Cause"; }
};

struct experimental_result_code : avp<enumerated<EXPERIMENTAL_RESULT>, 298, avp_flags::M>
{
	static constexpr char const* name() { return "Experimental-Result-Code"; }
};

struct inband_security_id : avp<unsigned32, 299, avp_flags::M>
{
	static constexpr char const* name() { return "Inband-Security-Id"; }
};


//--------------- grouped ------------------//
struct vendor_specific_application_id : avp_grouped<260, avp_flags::M, VENDOR::NONE
	, M< vendor_id, med::inf >
	, O< auth_application_id >
	, O< acct_application_id >
>
{
	static constexpr char const* name() { return "Vendor-Specific-Application-Id"; }
};

struct failed_avp : avp<med::octet_string<>, 279, avp_flags::M>
{
	static constexpr char const* name() { return "Failed-AVP"; }
};

struct proxy_info : avp_grouped<284, avp_flags::M, VENDOR::NONE
	, M< proxy_host >
	, M< proxy_state >
>
{
	static constexpr char const* name() { return "Proxy-Info"; }
};

struct experimental_result : avp_grouped<297, avp_flags::M, VENDOR::NONE
	, M< vendor_id >
	, M< experimental_result_code >
>
{
	static constexpr char const* name() { return "Experimental-Result"; }
};

}	//end: namespace diameter
