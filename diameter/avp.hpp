#pragma once
/**
@file
RFC6733/3588 DIAMETER protocol definition in med (https://github.com/cppden/med)

@copyright Denis Priyomov 2018
Distributed under the MIT License
(See accompanying file LICENSE or visit https://github.com/cppden/med)
*/

#include "med/value.hpp"
#include "med/mandatory.hpp"
#include "med/optional.hpp"
#include "med/placeholder.hpp"
#include "med/octet_string.hpp"
#include "med/sequence.hpp"

namespace diameter {

template <typename ...T>
using M = med::mandatory<T...>;
template <typename ...T>
using O = med::optional<T...>;


//to join message code and request/answer bit
constexpr uint32_t REQUEST = 0x80000000;

/***************************************************************
 * Header definitions
 ***************************************************************/
struct version : med::value<med::fixed<1, uint8_t>> {};
struct length : med::value<med::bytes<3>> {};

/*
0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|R P E T r r r r|
+-+-+-+-+-+-+-+-+
R(equest)   - If set, message is a request.  If cleared, message is an answer.
P(roxiable) - If set, message MAY be proxied, relayed or redirected.  If cleared, MUST be locally processed.
E(rror)     - If set, message contains a protocol error, commonly referred to as error messages. MUST NOT be set in request.
T(Potentially re-transmitted message) - This flag is set after a link failover procedure, to aid the removal of duplicate requests.
*/
struct cmd_flags : med::value<uint8_t>
{
	enum : value_type
	{
		R = 0x80,
		P = 0x40,
		E = 0x20,
		T = 0x10,
	};

	bool request() const                { return get() & R; }
	void request(bool v)                { set(v ? (get() | R) : (get() & ~R)); }

	bool proxiable() const              { return get() & P; }
	void proxiable(bool v)              { set(v ? (get() | P) : (get() & ~P)); }

	bool error() const                  { return get() & E; }
	void error(bool v)                  { set(v ? (get() | E) : (get() & ~E)); }

	bool retx() const                   { return get() & T; }
	void retx(bool v)                   { set(v ? (get() | T) : (get() & ~T)); }

	static constexpr char const* name() { return "Cmd-Flags"; }

	template <std::size_t N>
	void print(char (&sz)[N]) const
	{
		value_type const flags = get();
#define PB(bit) (flags&bit)?(#bit)[0]:'.'
		snprintf(sz, sizeof(sz)-1, "%c%c%c%c", PB(R), PB(P), PB(E), PB(T));
#undef PB
	}
};

struct cmd_code : med::value<med::bits<24>>
{
	//static constexpr char const* name()     { return "Cmd-Code"; }
	//non-fixed tag matching for ANY message
	static constexpr bool match(value_type) { return true; }
};

struct app_id : med::value<uint32_t>
{
	static constexpr char const* name() { return "App-Id"; }
};

struct hop_by_hop_id : med::value<uint32_t>
{
	static constexpr char const* name() { return "Hop-by-Hop-Id"; }
};

struct end_to_end_id : med::value<uint32_t>
{
	static constexpr char const* name() { return "End-to-End-Id"; }
};

/*
 0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |    Version    |                 Message Length                |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | command flags |                  Command-Code                 |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         Application-ID                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                      Hop-by-Hop Identifier                    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                      End-to-End Identifier                    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  AVPs ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-
*/
struct header : med::sequence<
	M< version >,
	med::placeholder::_length<>,
	M< cmd_flags >,
	M< cmd_code >,
	M< app_id >,
	M< hop_by_hop_id >,
	M< end_to_end_id >
>
{
	std::size_t get_tag() const                 { return get<cmd_code>().get() | (flags().request() ? REQUEST : 0); }
	void set_tag(std::size_t tag)               { ref<cmd_code>().set(tag & 0xFFFFFF); flags().request(tag & REQUEST); }

	cmd_flags const& flags() const              { return get<cmd_flags>(); }
	cmd_flags& flags()                          { return ref<cmd_flags>(); }

	app_id::value_type ap_id() const            { return get<app_id>().get(); }
	void ap_id(app_id::value_type id)           { ref<app_id>().set(id); }

	hop_by_hop_id::value_type hop_id() const    { return get<hop_by_hop_id>().get(); }
	void hop_id(hop_by_hop_id::value_type id)   { ref<hop_by_hop_id>().set(id); }

	end_to_end_id::value_type end_id() const    { return get<end_to_end_id>().get(); }
	void end_id(end_to_end_id::value_type id)   { ref<end_to_end_id>().set(id); }

	static constexpr char const* name()         { return "Header"; }
};


/***************************************************************
 * AVP definitions
 ***************************************************************/
struct avp_code : med::value<uint32_t>
{
	static constexpr char const* name()     { return "AVP-Code"; }
	//non-fixed tag matching for any_avp
	static constexpr bool match(value_type) { return true; }
};

template <avp_code::value_type CODE>
struct avp_code_fixed : med::value<med::fixed<CODE, avp_code::value_type>> {};

//mandatory flag
struct mandatory {};
//protected flag
struct protect {};

struct avp_flags : med::value<uint8_t>
{
	enum : value_type
	{
		V = 0x80, //vendor specific/vendor-id is present
		M = 0x40, //AVP is mandatory
		P = 0x20, //protected
	};

	bool mandatory() const                  { return get() & M; }
	void mandatory(bool v)                  { set(v ? (get() | M) : (get() & ~M)); }

	bool protect() const                    { return get() & P; }
	void protect(bool v)                    { set(v ? (get() | P) : (get() & ~P)); }

	static constexpr char const* name()	    { return "AVP-Flags"; }

	template <std::size_t N>
	void print(char (&sz)[N]) const
	{
		value_type const flags = get();
#define PB(bit) (flags&bit)?(#bit)[0]:'.'
		std::snprintf(sz, sizeof(sz)-1, "%c%c%c", PB(V), PB(M), PB(P));
#undef PB
	}
};

//Vendor
enum class VENDOR : uint32_t
{
	NONE     = 0,
	HP       = 11, //Hewlett Packard
	SUN      = 42, //Sun Microsystems, Inc.
	MERIT    = 61, //Merit Networks
	USR      = 42, //US Robotics Corp.
	ERICSSON = 193,
	TGPP2    = 5535, //3GPP2
	TGPP     = 10415, //3GPP
	VODAFONE = 12645,
	ETSI     = 13019,
	NOKIA    = 28458,
	TGPPCXDX = 16777216, //3GPP Cx/Dx
	TGPPSH   = 16777217, //3GPP Sh
};

struct vendor : med::value<uint32_t>
{
	static constexpr char const* name()     { return "Vendor"; }

	struct has
	{
		template <class HDR>
		bool operator()(HDR const& hdr) const
		{
			return hdr.template as<avp_flags>().get() & avp_flags::V;
		}
	};
};

namespace detail {
/*
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                           AVP Code                            |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |V M P r r r r r|                  AVP Length                   |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                        Vendor-ID (opt)                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |    Data ...
 +-+-+-+-+-+-+-+-+
*/
template <class VALUE, uint32_t CODE, uint8_t FLAGS, VENDOR VND>
struct avp_header : med::sequence<
		M< avp_flags >,
		med::placeholder::_length<(CODE != 0) ? -4 : 0>, //include AVP-Code
		O< vendor, vendor::has >,
		M< VALUE >
	>
{
	using length_type = length;
	using padding = med::padding<uint32_t, false>;

	static constexpr uint32_t id = CODE;

	auto const& flags() const               { return this->template get<avp_flags>(); }
	auto& flags()                           { return this->template ref<avp_flags>(); }

	VENDOR get_vendor() const
	{
		auto* p = this->template get<vendor>();
		return (p) ? static_cast<VENDOR>(p->get()) : VENDOR::NONE;
	}

	static constexpr char const* name()     { return "AVP"; }

	bool is_set() const                     { return body().is_set(); }

	avp_header()
	{
		if constexpr (VND == VENDOR::NONE)
		{
			this->template ref<avp_flags>().set(FLAGS & ~avp_flags::V);
		}
		else
		{
			this->template ref<vendor>().set(VND);
			this->template ref<avp_flags>().set(FLAGS | avp_flags::V);
		}
	}

protected:
	VALUE& body()                           { return this->template ref<VALUE>(); }
	VALUE const& body() const               { return this->template get<VALUE>(); }
};

} //end: namespace detail


/***************************************************************
 * Non-grouped/single value AVPs
 ***************************************************************/
template <
		class VALUE,
		avp_code::value_type CODE,
		uint8_t FLAGS = 0,
		VENDOR VND = VENDOR::NONE,
		class Enable = void
	>
struct avp;

template <class VALUE, avp_code::value_type CODE, uint8_t FLAGS, VENDOR VND>
struct avp<
		VALUE, CODE, FLAGS, VND,
		std::enable_if_t<std::is_same_v<med::IE_VALUE, typename VALUE::ie_type>>
	> : detail::avp_header<VALUE, CODE, FLAGS, VND>
	, med::tag_t< avp_code_fixed<CODE> >
{
	//using value_type = typename VALUE::value_type;
	auto get() const                                { return this->body().get(); }
	template <typename T>
	auto set(T v)                                   { return this->body().set(v); }
};

template <class VALUE, avp_code::value_type CODE, uint8_t FLAGS, VENDOR VND>
struct avp<
		VALUE, CODE, FLAGS, VND,
		std::enable_if_t<std::is_same_v<med::IE_OCTET_STRING, typename VALUE::ie_type>>
	> : detail::avp_header<VALUE, CODE, FLAGS, VND>
	, med::tag_t< avp_code_fixed<CODE> >
{
	std::size_t size() const                        { return this->body().size(); }
	uint8_t const* data() const                     { return this->body().data(); }
	uint8_t* data()                                 { return this->body().data(); }
	using const_iterator = typename VALUE::const_iterator;
	const_iterator begin() const                    { return data(); }
	const_iterator end() const                      { return begin() + size(); }

	void clear()                                    { this->body().clear(); }

//	template <class... ARGS>
//	auto copy(base_t const& from, ARGS&&... args)   { return body().copy(from, std::forward<ARGS>(args)...); }

	template <class T, class Enable = std::enable_if_t<std::is_pointer_v<decltype(((T*)0)->data())>>>
	auto set(T const& v)                            { return set(v.size(), v.data()); }
	auto set(std::size_t len, void const* data)     { return this->body().set(len, data); }
};

/***************************************************************
 * Grouped/multi-value AVPs
 ***************************************************************/
template <avp_code::value_type CODE, uint8_t FLAGS, VENDOR VND, class... AVPs>
struct avp_grouped : detail::avp_header<
		med::set<avp_code, AVPs...>
		, CODE, FLAGS, VND
	>
	, med::tag_t< avp_code_fixed<CODE> >
{
	static_assert(sizeof...(AVPs) > 1, "USE PLAIN AVP FOR SINGLE VALUE");

	template <class FIELD>
	FIELD& ref()                            { return this->body().template ref<FIELD>(); }
	template <class FIELD>
	decltype(auto) get() const              { return this->body().template get<FIELD>(); }

	template <class FIELD, class... ARGS>
	FIELD* push_back(ARGS&&... args)        { return this->body().template push_back<FIELD>(std::forward<ARGS>(args)...); }

	template <class FIELD>
	std::size_t count() const               { return this->body().template count<FIELD>(); }
};

struct any_avp : med::sequence<
		M< avp_code >,
		M< avp_flags >,
		med::placeholder::_length<>,
		O< vendor, vendor::has >,
		M< med::octet_string<> >
	>
	, med::tag_t<avp_code>
{
	using length_type = length;
	using padding = med::padding<uint32_t, false>;

	bool is_set() const                 { return get<med::octet_string<>>().is_set(); }
};

}	//end: namespace diameter
