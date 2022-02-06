#pragma once
/**
@file
RFC6733/3588 DIAMETER protocol definition in med (https://github.com/cppden/med)

@copyright Denis Priyomov 2018
Distributed under the MIT License
(See accompanying file LICENSE or visit https://github.com/cppden/med)
*/

#include "med/choice.hpp"

#include "base_avps.hpp"

namespace diameter {

/*
<CER> ::= < Diameter Header: 257, REQ >
	{ Origin-Host }
	{ Origin-Realm }
	1* { Host-IP-Address }
	{ Vendor-Id }
	{ Product-Name }
	[ Origin-State-Id ]
	* [ Supported-Vendor-Id ]
	* [ Auth-Application-Id ]
	* [ Inband-Security-Id ]
	* [ Acct-Application-Id ]
	* [ Vendor-Specific-Application-Id ]
	[ Firmware-Revision ]
	* [ AVP ]
*/
struct CER : med::set<
	M< origin_host >,
	M< origin_realm >,
	M< host_ip_address, med::inf >,
	M< vendor_id >,
	M< product_name >,
	O< origin_state_id >,
	O< supported_vendor_id, med::inf >,
	O< auth_application_id, med::inf >,
	O< inband_security_id,  med::inf >,
	O< acct_application_id, med::inf >,
	O< vendor_specific_application_id, med::inf >,
	O< firmware_revision >,
	O< any_avp, med::inf >
>
{
	static constexpr std::size_t code = 257;
	static constexpr char const* name() { return "Capabilities-Exchange-Request"; }
};

/*
<CEA> ::= < Diameter Header: 257 >
	{ Result-Code }
	{ Origin-Host }
	{ Origin-Realm }
	1* { Host-IP-Address }
	{ Vendor-Id }
	{ Product-Name }
	[ Origin-State-Id ]
	[ Error-Message ]
	* [ Failed-AVP ]
	* [ Supported-Vendor-Id ]
	* [ Auth-Application-Id ]
	* [ Inband-Security-Id ]
	* [ Acct-Application-Id ]
	* [ Vendor-Specific-Application-Id ]
	[ Firmware-Revision ]
	* [ AVP ]
*/
struct CEA : med::set<
	M< result_code >,
	M< origin_host >,
	M< origin_realm >,
	M< host_ip_address, med::inf >,
	M< vendor_id >,
	M< product_name >,
	O< origin_state_id >,
	O< error_message >,
	O< failed_avp, med::inf >,
	O< supported_vendor_id, med::inf >,
	O< auth_application_id, med::inf >,
	O< inband_security_id,  med::inf >,
	O< acct_application_id, med::inf >,
	O< vendor_specific_application_id, med::inf >,
	O< firmware_revision >,
	O< any_avp, med::inf >
>
{
	static constexpr std::size_t code = 257;
	static constexpr char const* name() { return "Capabilities-Exchange-Answer"; }
};


/*
<DPR>  ::= < Diameter Header: 282, REQ >
	{ Origin-Host }
	{ Origin-Realm }
	{ Disconnect-Cause }
*/
struct DPR : med::set<
	M< origin_host >,
	M< origin_realm >,
	M< disconnect_cause >,
	O< any_avp, med::inf >
>
{
	static constexpr std::size_t code = 282;
	static constexpr char const* name() { return "Disconnect-Peer-Request"; }
};

/*
<DPA>  ::= < Diameter Header: 282 >
	{ Result-Code }
	{ Origin-Host }
	{ Origin-Realm }
	[ Error-Message ]
	* [ Failed-AVP ]
*/
struct DPA : med::set<
	M< result_code >,
	M< origin_host >,
	M< origin_realm >,
	O< error_message >,
	O< failed_avp, med::inf >,
	O< any_avp, med::inf >
>
{
	static constexpr std::size_t code = 282;
	static constexpr char const* name() { return "Disconnect-Peer-Answer"; }
};

/*
<DWR>  ::= < Diameter Header: 280, REQ >
	{ Origin-Host }
	{ Origin-Realm }
	[ Origin-State-Id ]
*/
struct DWR : med::set<
	M< origin_host >,
	M< origin_realm >,
	O< origin_state_id >,
	O< any_avp, med::inf >
>
{
	static constexpr std::size_t code = 280;
	static constexpr char const* name() { return "Device-Watchdog-Request"; }
};

/*
<DWA>  ::= < Diameter Header: 280 >
	{ Result-Code }
	{ Origin-Host }
	{ Origin-Realm }
	[ Error-Message ]
	* [ Failed-AVP ]
	[ Origin-State-Id ]
*/
struct DWA : med::set<
	M< result_code >,
	M< origin_host >,
	M< origin_realm >,
	O< error_message >,
	O< failed_avp, med::inf >,
	O< origin_state_id >,
	O< any_avp, med::inf >
>
{
	static constexpr std::size_t code = 280;
	static constexpr char const* name() { return "Device-Watchdog-Answer"; }
};

/*
<RAR>  ::= < Diameter Header: 258, REQ, PXY >
	< Session-Id >
	{ Origin-Host }
	{ Origin-Realm }
	{ Destination-Realm }
	{ Destination-Host }
	{ Auth-Application-Id }
	{ Re-Auth-Request-Type }
	[ User-Name ]
	[ Origin-State-Id ]
	* [ Proxy-Info ]
	* [ Route-Record ]
	* [ AVP ]
*/
struct RAR : med::set<
	M< session_id >,
	M< origin_host >,
	M< origin_realm >,
	M< destination_host >,
	M< destination_realm >,
	M< auth_application_id >,
	M< re_auth_request_type >,
	O< user_name >,
	O< origin_state_id >,
	O< proxy_info, med::inf >,
	O< route_record, med::inf >,
	O< any_avp, med::inf >
>
{
	static constexpr std::size_t code = 258;
	static constexpr char const* name() { return "Re-Auth-Request"; }
};

/*
<RAA>  ::= < Diameter Header: 258, PXY >
	< Session-Id >
	{ Result-Code }
	{ Origin-Host }
	{ Origin-Realm }
	[ User-Name ]
	[ Origin-State-Id ]
	[ Error-Message ]
	[ Error-Reporting-Host ]
	[ Failed-AVP ]
	* [ Redirect-Host ]
	[ Redirect-Host-Usage ]
	[ Redirect-Max-Cache-Time ]
	* [ Proxy-Info ]
	* [ AVP ]
*/
struct RAA : med::set<
	M< session_id >,
	M< result_code >,
	M< origin_host >,
	M< origin_realm >,
	O< user_name >,
	O< origin_state_id >,
	O< error_message >,
	O< error_reporting_host >,
	O< failed_avp >,
	O< redirect_host, med::inf >,
	O< redirect_host_usage >,
	O< redirect_max_cache_time >,
	O< proxy_info, med::inf >,
	O< any_avp, med::inf >
>
{
	static constexpr std::size_t code = 258;
	static constexpr char const* name() { return "Re-Auth-Answer"; }
};

/*
<STR>  ::= < Diameter Header: 275, REQ, PXY >
	< Session-Id >
	{ Origin-Host }
	{ Origin-Realm }
	{ Destination-Realm }
	{ Auth-Application-Id }
	{ Termination-Cause }
	[ User-Name ]
	[ Destination-Host ]
	* [ Class ]
	[ Origin-State-Id ]
	* [ Proxy-Info ]
	* [ Route-Record ]
	* [ AVP ]
*/
struct STR : med::set<
	M< session_id >,
	M< origin_host >,
	M< origin_realm >,
	M< destination_realm >,
	M< auth_application_id >,
	M< termination_cause >,
	O< user_name >,
	O< destination_host >,
	O< Class, med::inf >,
	O< origin_state_id >,
	O< proxy_info, med::inf >,
	O< route_record, med::inf >,
	O< any_avp, med::inf >
>
{
	static constexpr std::size_t code = 275;
	static constexpr char const* name() { return "Session-Termination-Request"; }
};

/*
<STA> ::= < Diameter Header: 275, PXY >
	< Session-Id >
	{ Result-Code }
	{ Origin-Host }
	{ Origin-Realm }
	[ User-Name ]
	* [ Class ]
	[ Error-Message ]
	[ Error-Reporting-Host ]
	[ Failed-AVP ]
	[ Origin-State-Id ]
	* [ Redirect-Host ]
	[ Redirect-Host-Usage ]
	[ Redirect-Max-Cache-Time ]
	* [ Proxy-Info ]
	* [ AVP ]
*/
struct STA : med::set<
	M< session_id >,
	M< result_code >,
	M< origin_host >,
	M< origin_realm >,
	O< user_name >,
	O< Class, med::inf >,
	O< error_message >,
	O< error_reporting_host >,
	O< failed_avp >,
	O< origin_state_id >,
	O< redirect_host, med::inf >,
	O< redirect_host_usage >,
	O< redirect_max_cache_time >,
	O< proxy_info, med::inf >,
	O< any_avp, med::inf >
>
{
	static constexpr std::size_t code = 275;
	static constexpr char const* name() { return "Session-Termination-Answer"; }
};

/*
<ASR>  ::= < Diameter Header: 274, REQ, PXY >
	< Session-Id >
	{ Origin-Host }
	{ Origin-Realm }
	{ Destination-Realm }
	{ Destination-Host }
	{ Auth-Application-Id }
	[ User-Name ]
	[ Origin-State-Id ]
	* [ Proxy-Info ]
	* [ Route-Record ]
	* [ AVP ]
*/
struct ASR : med::set<
	M< session_id >,
	M< origin_host >,
	M< origin_realm >,
	M< destination_realm >,
	M< destination_host >,
	M< auth_application_id >,
	M< termination_cause >,
	O< user_name >,
	O< origin_state_id >,
	O< proxy_info, med::inf >,
	O< route_record, med::inf >,
	O< any_avp, med::inf >
>
{
	static constexpr std::size_t code = 274;
	static constexpr char const* name() { return "Abort-Session-Request"; }
};

/*
<ASA>  ::= < Diameter Header: 274, PXY >
	< Session-Id >
	{ Result-Code }
	{ Origin-Host }
	{ Origin-Realm }
	[ User-Name ]
	[ Origin-State-Id ]
	[ Error-Message ]
	[ Error-Reporting-Host ]
	[ Failed-AVP ]
	* [ Redirect-Host ]
	[ Redirect-Host-Usage ]
	[ Redirect-Max-Cache-Time ]
	* [ Proxy-Info ]
	* [ AVP ]
*/
struct ASA : med::set<
	M< session_id >,
	M< result_code >,
	M< origin_host >,
	M< origin_realm >,
	O< user_name >,
	O< origin_state_id >,
	O< error_message >,
	O< error_reporting_host >,
	O< failed_avp >,
	O< redirect_host, med::inf >,
	O< redirect_host_usage >,
	O< redirect_max_cache_time >,
	O< proxy_info, med::inf >,
	O< any_avp, med::inf >
>
{
	static constexpr std::size_t code = 274;
	static constexpr char const* name() { return "Abort-Session-Answer"; }
};

/*
<ACR> ::= < Diameter Header: 271, REQ, PXY >
	< Session-Id >
	{ Origin-Host }
	{ Origin-Realm }
	{ Destination-Realm }
	{ Accounting-Record-Type }
	{ Accounting-Record-Number }
	[ Acct-Application-Id ]
	[ Vendor-Specific-Application-Id ]
	[ User-Name ]
	[ Destination-Host ]
	[ Accounting-Sub-Session-Id ]
	[ Acct-Session-Id ]
	[ Acct-Multi-Session-Id ]
	[ Acct-Interim-Interval ]
	[ Accounting-Realtime-Required ]
	[ Origin-State-Id ]
	[ Event-Timestamp ]
	* [ Proxy-Info ]
	* [ Route-Record ]
	* [ AVP ]
*/
struct ACR : med::set<
	M< session_id >,
	M< origin_host >,
	M< origin_realm >,
	M< destination_realm >,
	M< acct_record_type >,
	M< acct_record_number >,
	O< acct_application_id >,
	O< vendor_specific_application_id >,
	O< user_name >,
	O< destination_host >,
	O< acct_sub_session_id >,
	O< acct_session_id >,
	O< acct_multi_session_id >,
	O< acct_interim_interval >,
	O< acct_realtime_required >,
	O< origin_state_id >,
	O< event_timestamp >,
	O< proxy_info, med::inf >,
	O< route_record, med::inf >,
	O< any_avp, med::inf >
>
{
	static constexpr std::size_t code = 271;
	static constexpr char const* name() { return "Accounting-Request"; }
};

/*
<ACA> ::= < Diameter Header: 271, PXY >
	< Session-Id >
	{ Result-Code }
	{ Origin-Host }
	{ Origin-Realm }
	{ Accounting-Record-Type }
	{ Accounting-Record-Number }
	[ Acct-Application-Id ]
	[ Vendor-Specific-Application-Id ]
	[ User-Name ]
	[ Accounting-Sub-Session-Id ]
	[ Acct-Session-Id ]
	[ Acct-Multi-Session-Id ]
	[ Error-Message ]
	[ Error-Reporting-Host ]
	[ Failed-AVP ]
	[ Acct-Interim-Interval ]
	[ Accounting-Realtime-Required ]
	[ Origin-State-Id ]
	[ Event-Timestamp ]
	* [ Proxy-Info ]
	* [ AVP ]
*/
struct ACA : med::set<
	M< session_id >,
	M< result_code >,
	M< origin_host >,
	M< origin_realm >,
	M< acct_record_type >,
	M< acct_record_number >,
	O< acct_application_id >,
	O< vendor_specific_application_id >,
	O< user_name >,
	O< acct_sub_session_id >,
	O< acct_session_id >,
	O< acct_multi_session_id >,
	O< error_message >,
	O< error_reporting_host >,
	O< failed_avp >,
	O< acct_interim_interval >,
	O< acct_realtime_required >,
	O< origin_state_id >,
	O< event_timestamp >,
	O< proxy_info, med::inf >,
	O< any_avp, med::inf >
>
{
	static constexpr std::size_t code = 271;
	static constexpr char const* name() { return "Accounting-Answer"; }
};


struct any_request : med::value<uint32_t>
{
	static constexpr char const* name()         { return "Request"; }
	//non-fixed tag matching any Diameter request
	static constexpr bool match(value_type v)   { return (v & REQUEST) != 0; }
};
struct Request : med::set<
	O< session_id >,
	O< origin_host >,
	O< origin_realm >,
	O< destination_realm >,
	O< destination_host >,
	O< any_avp, med::inf >
>
{
	static constexpr char const* name() { return "Unknown-Request"; }
};

struct any_answer : med::value<uint32_t>
{
	static constexpr char const* name()         { return "Answer"; }
	//non-fixed tag matching any Diameter request
	static constexpr bool match(value_type v)   { return (v & REQUEST) == 0; }
};

struct Answer : med::set<
	M< result_code >,
	O< session_id >,
	O< origin_host >,
	O< origin_realm >,
	O< error_message >,
	O< any_avp, med::inf >
>
{
	static constexpr char const* name() { return "Unknown-Answer"; }
};

//using request = med::tag<med::value<med::fixed<REQUEST | MSG::code, uint32_t>>, MSG>;
//using answer = med::tag<med::value<med::fixed<MSG::code, uint32_t>>, MSG>;
template <class MSG>
using request = med::mandatory<med::value<med::fixed<REQUEST | MSG::code, uint32_t>>, MSG>;
template <class MSG>
using answer = med::mandatory<med::value<med::fixed<MSG::code, uint32_t>>, MSG>;

//--- DIAMETER protocol base part
struct base : med::choice< header
	, request<CER>
	, answer<CEA>
	, request<DPR>
	, answer<DPA>
	, request<DWR>
	, answer<DWA>
	, request<RAR>
	, answer<RAA>
	, request<STR>
	, answer<STA>
	, request<ASR>
	, answer<ASA>
	, request<ACR>
	, answer<ACA>
	, med::mandatory<any_request, Request>
	, med::mandatory<any_answer, Answer>
>
{
	using length_type = length;
};

}	//end: namespace diameter
