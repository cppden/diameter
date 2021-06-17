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
	  M< origin_host >
	, M< origin_realm >
	, M< host_ip_address, med::inf >
	, M< vendor_id >
	, M< product_name >
	, O< origin_state_id >
	, O< supported_vendor_id, med::inf >
	, O< auth_application_id, med::inf >
	, O< inband_security_id,  med::inf >
	, O< acct_application_id, med::inf >
	, O< vendor_specific_application_id, med::inf >
	, O< firmware_revision >
	, O< any_avp, med::inf >
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
	  M< result_code >
	, M< origin_host >
	, M< origin_realm >
	, M< host_ip_address, med::inf >
	, M< vendor_id >
	, M< product_name >
	, O< origin_state_id >
	, O< error_message >
	, O< failed_avp, med::inf >
	, O< supported_vendor_id, med::inf >
	, O< auth_application_id, med::inf >
	, O< inband_security_id,  med::inf >
	, O< acct_application_id, med::inf >
	, O< vendor_specific_application_id, med::inf >
	, O< firmware_revision >
	, O< any_avp, med::inf >
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
	  M< origin_host >
	, M< origin_realm >
	, M< disconnect_cause >
	, O< any_avp, med::inf >
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
	  M< result_code >
	, M< origin_host >
	, M< origin_realm >
	, O< error_message >
	, O< failed_avp, med::inf >
	, O< any_avp, med::inf >
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
	  M< origin_host >
	, M< origin_realm >
	, O< origin_state_id >
	, O< any_avp, med::inf >
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
	  M< result_code >
	, M< origin_host >
	, M< origin_realm >
	, O< error_message >
	, O< failed_avp, med::inf >
	, O< origin_state_id >
	, O< any_avp, med::inf >
>
{
	static constexpr std::size_t code = 280;
	static constexpr char const* name() { return "Device-Watchdog-Answer"; }
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
>
{
	using length_type = typename length::length_type;
};

}	//end: namespace diameter
