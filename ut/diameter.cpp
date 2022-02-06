#include <cstdio>
#include <string_view>

#include "med/encoder_context.hpp"
#include "med/decoder_context.hpp"
#include "med/octet_encoder.hpp"
#include "med/octet_decoder.hpp"
#include "med/encode.hpp"
#include "med/decode.hpp"

#include "diameter/base.hpp"

#include "ut.hpp"

using namespace std::string_view_literals;

uint8_t const cer_encoded1[] = {
		0x01, 0x00, 0x01, 0x14, //VER(1), LEN(3)
		0x80, 0x00, 0x01, 0x01, //R.P.E.T(1), CMD(3) = 257
		0x00, 0x00, 0x00, 0x00, //APP-ID
		0x22, 0x22, 0x22, 0x22, //H2H-ID
/*10*/	0x55, 0x55, 0x55, 0x55, //E2E-ID

		0x00, 0x00, 0x01, 0x08, //AVP-CODE = 264 OrigHost
		0x40, 0x00, 0x00, 17, //V.M.P(1), LEN(3) = 17 + padding
		'O', 'r', 'i', 'g',
/*20*/	'.', 'H', 'o', 's',
		't',   0,   0,   0,

		0x00, 0x00, 0x01, 0x28, //AVP-CODE = 296 OrigRealm
		0x40, 0x00, 0x00, 22, //V.M.P(1), LEN(3) = 22 + padding
/*30*/	'o', 'r', 'i', 'g',
		'.', 'r', 'e', 'a',
		'l', 'm', '.', 'n',
		'e', 't',   0,   0,

/*40*/	0x00, 0x00, 0x01, 0x01, //AVP-CODE = 257 Host-IP-Addr AVP
		0x40, 0x00, 0x00, 0x0E, //V.M.P(1), LEN(3) = 14 + padding = 16
		0x00, 0x01, 0x01, 0x02,
		0x03, 0x04, 0x00, 0x00,

/*50*/	0x00, 0x00, 0x01, 0x0A, //AVP-CODE = 266 Vendor-Id AVP
		0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
		0x00, 0x00, 0x00, 0x00, //id = 0

		0x00, 0x00, 0x01, 0x0D, //AVP-CODE = 269 Prod-Name AVP
/*60*/	0x00, 0x00, 0x00, 0x10, //V.M.P(1), LEN(3) = 16
		'b', 'a', 's', 'e',
		':', 'd', 'i', 'a',

		0x00, 0x00, 0x01, 0x09, //AVP-CODE = 265 Supported-Vendor-Id AVP
/*70*/	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
		0x00, 0x00, 0x28, 0xAF, //id = 3GPP

		0x00, 0x00, 0x01, 0x09, //AVP-CODE = 265 Supported-Vendor-Id AVP
		0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
		0x00, 0x00, 0x6F, 0x2A, //id = NSN

		0x00, 0x00, 0x01, 0x02, //AVP-CODE = 258 Auth-App-Id AVP
		0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
		0x00, 0x00, 0x00, 0x00, //id = 0

		0x00, 0x00, 0x01, 0x02, //AVP-CODE = 258 Auth-App-Id AVP
		0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
		0x01, 0x00, 0x00, 0x23, //id = S6a

		0x00, 0x00, 0x01, 0x02, //AVP-CODE = 258 Auth-App-Id AVP
		0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
		0x01, 0x00, 0x00, 0x16, //id = Gx

		0x00, 0x00, 0x01, 0x02, //AVP-CODE = 258 Auth-App-Id AVP
		0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
		0x01, 0x00, 0x00, 0x32, //id = Gxx

		0x00, 0x00, 0x01, 0x04, //AVP-CODE = 260 Vendor-Specific-App-Id (grouped)
		0x40, 0x00, 0x00, 0x20, //V.M.P(1), LEN(3) = 32
		0x00, 0x00, 0x01, 0x0A, //Vendor-Id AVP
		0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
		0x00, 0x00, 0x28, 0xAF, //id = 3GPP
		0x00, 0x00, 0x01, 0x02, //Auth-App-Id AVP
		0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
		0x01, 0x00, 0x00, 0x23, //id = S6A

		0x00, 0x00, 0x01, 0x04, //AVP-CODE = 260 Vendor-Specific-App-Id (grouped)
		0x40, 0x00, 0x00, 0x20, //V.M.P(1), LEN(3) = 32
		0x00, 0x00, 0x01, 0x0A, //Vendor-Id AVP
		0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
		0x00, 0x00, 0x28, 0xAF, //id = 3GPP
		0x00, 0x00, 0x01, 0x02, //Auth-App-Id AVP
		0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
		0x01, 0x00, 0x00, 0x16, //id = Gx

		0x00, 0x00, 0x01, 0x04, //AVP-CODE = 260 Vendor-Specific-App-Id (grouped)
		0x40, 0x00, 0x00, 0x20, //V.M.P(1), LEN(3) = 32
		0x00, 0x00, 0x01, 0x0A, //Vendor-Id AVP
		0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
		0x00, 0x00, 0x28, 0xAF, //id = 3GPP
		0x00, 0x00, 0x01, 0x02, //Auth-App-Id AVP
		0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
		0x01, 0x00, 0x00, 0x32, //id = Gxx
};

uint8_t const cea_encoded1[] = {
	0x01, 0x00, 0x01, 0x20, //VER(1), LEN(3)
	0x00, 0x00, 0x01, 0x01, //R.P.E.T(1), CMD(3) = 257
	0x00, 0x00, 0x00, 0x00, //APP-ID
	0x22, 0x22, 0x22, 0x22, //H2H-ID
	0x55, 0x55, 0x55, 0x55, //E2E-ID

	0x00, 0x00, 0x01, 0x0C, //AVP-CODE = 268 Result Code
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3)=12
	0x00, 0x00, 0x07, 0xD1, //result = 2001

	0x00, 0x00, 0x01, 0x08, //AVP-CODE = 264 OrigHost
	0x40, 0x00, 0x00, 0x11, //V.M.P(1), LEN(3) = 17 + padding
	'O', 'r', 'i', 'g',
	'.', 'H', 'o', 's',
	't',   0,   0,   0,

	0x00, 0x00, 0x01, 0x28, //AVP-CODE = 296 OrigRealm
	0x40, 0x00, 0x00, 0x16, //V.M.P(1), LEN(3) = 22 + padding
	'o', 'r', 'i', 'g',
	'.', 'r', 'e', 'a',
	'l', 'm', '.', 'n',
	'e', 't',   0,   0,

	0x00, 0x00, 0x01, 0x01, //AVP-CODE = 257 Host-IP-Addr AVP
	0x40, 0x00, 0x00, 0x0E, //V.M.P(1), LEN(3) = 14 + padding = 16
	0x00, 0x01, 0x01, 0x02,
	0x03, 0x04, 0x00, 0x00,

	0x00, 0x00, 0x01, 0x0A, //AVP-CODE = 266 Vendor-Id AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x00, 0x00, 0x00, 0x00, //id = 0

	0x00, 0x00, 0x01, 0x0D, //AVP-CODE = 269 Prod-Name AVP
	0x00, 0x00, 0x00, 0x10, //V.M.P(1), LEN(3) = 16
	'b', 'a', 's', 'e',
	':', 'd', 'i', 'a',

	0x00, 0x00, 0x01, 0x09, //AVP-CODE = 265 Supported-Vendor-Id AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x00, 0x00, 0x28, 0xAF, //id = 3GPP

	0x00, 0x00, 0x01, 0x09, //AVP-CODE = 265 Supported-Vendor-Id AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x00, 0x00, 0x6F, 0x2A, //id = NSN

	0x00, 0x00, 0x01, 0x02, //AVP-CODE = 258 Auth-App-Id AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x00, 0x00, 0x00, 0x00, //id = 0

	0x00, 0x00, 0x01, 0x02, //AVP-CODE = 258 Auth-App-Id AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x01, 0x00, 0x00, 0x23, //id = S6a

	0x00, 0x00, 0x01, 0x02, //AVP-CODE = 258 Auth-App-Id AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x01, 0x00, 0x00, 0x16, //id = Gx

	0x00, 0x00, 0x01, 0x02, //AVP-CODE = 258 Auth-App-Id AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x01, 0x00, 0x00, 0x32, //id = Gxx

	0x00, 0x00, 0x01, 0x04, //AVP-CODE = 260 Vendor-Specific-App-Id (grouped)
	0x40, 0x00, 0x00, 0x20, //V.M.P(1), LEN(3) = 32
	0x00, 0x00, 0x01, 0x0A, //Vendor-Id AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x00, 0x00, 0x28, 0xAF, //id = 3GPP
	0x00, 0x00, 0x01, 0x02, //Auth-App-Id AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x01, 0x00, 0x00, 0x23, //id = S6A

	0x00, 0x00, 0x01, 0x04, //AVP-CODE = 260 Vendor-Specific-App-Id (grouped)
	0x40, 0x00, 0x00, 0x20, //V.M.P(1), LEN(3) = 32
	0x00, 0x00, 0x01, 0x0A, //Vendor-Id AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x00, 0x00, 0x28, 0xAF, //id = 3GPP
	0x00, 0x00, 0x01, 0x02, //Auth-App-Id AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x01, 0x00, 0x00, 0x16, //id = Gx

	0x00, 0x00, 0x01, 0x04, //AVP-CODE = 260 Vendor-Specific-App-Id (grouped)
	0x40, 0x00, 0x00, 0x20, //V.M.P(1), LEN(3) = 32
	0x00, 0x00, 0x01, 0x0A, //Vendor-Id AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x00, 0x00, 0x28, 0xAF, //id = 3GPP
	0x00, 0x00, 0x01, 0x02, //Auth-App-Id AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x01, 0x00, 0x00, 0x32, //id = Gxx
};

uint8_t const dpr_encoded1[] = {
	0x01, 0x00, 0x00, 0x4C, //VER(1), LEN(3)
	0x80, 0x00, 0x01, 0x1A, //R.P.E.T(1), CMD(3) = 282
	0x00, 0x00, 0x00, 0x00, //APP-ID
	0x22, 0x22, 0x22, 0x22, //H2H-ID
	0x55, 0x55, 0x55, 0x55, //E2E-ID

	0x00, 0x00, 0x01, 0x08, //AVP-CODE = 264 OrigHost
	0x40, 0x00, 0x00, 0x11, //V.M.P(1), LEN(3) = 17 + padding
	'O', 'r', 'i', 'g',
	'.', 'H', 'o', 's',
	't',   0,   0,   0,

	0x00, 0x00, 0x01, 0x28, //AVP-CODE = 296 OrigRealm
	0x40, 0x00, 0x00, 0x16, //V.M.P(1), LEN(3) = 22 + padding
	'o', 'r', 'i', 'g',
	'.', 'r', 'e', 'a',
	'l', 'm', '.', 'n',
	'e', 't',   0,   0,

	0x00, 0x00, 0x01, 0x11, //AVP = 273 Disconnect-Cause AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x00, 0x00, 0x00, 0x02, //cause = 2
};

uint8_t const dpa_encoded1[] = {
	0x01, 0x00, 0x00, 0x4C, //VER(1), LEN(3)
	0x00, 0x00, 0x01, 0x1A, //R.P.E.T(1), CMD(3) = 282
	0x00, 0x00, 0x00, 0x00, //APP-ID
	0x22, 0x22, 0x22, 0x22, //H2H-ID
	0x55, 0x55, 0x55, 0x55, //E2E-ID

	0x00, 0x00, 0x01, 0x0C, //AVP = 268 Result Code
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x00, 0x00, 0x0B, 0xBC, //result = 3004

	0x00, 0x00, 0x01, 0x08, //AVP-CODE = 264 OrigHost
	0x40, 0x00, 0x00, 0x11, //V.M.P(1), LEN(3) = 17 + padding
	'O', 'r', 'i', 'g',
	'.', 'H', 'o', 's',
	't',   0,   0,   0,

	0x00, 0x00, 0x01, 0x28, //AVP-CODE = 296 OrigRealm
	0x40, 0x00, 0x00, 0x16, //V.M.P(1), LEN(3) = 22 + padding
	'o', 'r', 'i', 'g',
	'.', 'r', 'e', 'a',
	'l', 'm', '.', 'n',
	'e', 't',   0,   0,
};

uint8_t const dwr_encoded1[] = {
	0x01, 0x00, 0x00, 0x40, //VER(1), LEN(3)
	0x80, 0x00, 0x01, 0x18, //R.P.E.T(1), CMD(3) = 280
	0x00, 0x00, 0x00, 0x00, //APP-ID
	0x22, 0x22, 0x22, 0x22, //H2H-ID
	0x55, 0x55, 0x55, 0x55, //E2E-ID

	0x00, 0x00, 0x01, 0x08, //AVP-CODE = 264 OrigHost
	0x40, 0x00, 0x00, 0x11, //V.M.P(1), LEN(3) = 17 + padding
	'O', 'r', 'i', 'g',
	'.', 'H', 'o', 's',
	't',   0,   0,   0,

	0x00, 0x00, 0x01, 0x28, //AVP-CODE = 296 OrigRealm
	0x40, 0x00, 0x00, 0x16, //V.M.P(1), LEN(3) = 22 + padding
	'o', 'r', 'i', 'g',
	'.', 'r', 'e', 'a',
	'l', 'm', '.', 'n',
	'e', 't',   0,   0,
};

uint8_t const dwa_encoded1[] = {
	0x01, 0x00, 0x00, 0x4C, //VER(1), LEN(3)
	0x00, 0x00, 0x01, 0x18, //R.P.E.T(1), CMD(3) = 280
	0x00, 0x00, 0x00, 0x00, //APP-ID
	0x22, 0x22, 0x22, 0x22, //H2H-ID
	0x55, 0x55, 0x55, 0x55, //E2E-ID

	0x00, 0x00, 0x01, 0x0C, //AVP = 268 Result Code
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x00, 0x00, 0x0B, 0xBC, //result = 3004

	0x00, 0x00, 0x01, 0x08, //AVP-CODE = 264 OrigHost
	0x40, 0x00, 0x00, 0x11, //V.M.P(1), LEN(3) = 17 + padding
	'O', 'r', 'i', 'g',
	'.', 'H', 'o', 's',
	't',   0,   0,   0,

	0x00, 0x00, 0x01, 0x28, //AVP-CODE = 296 OrigRealm
	0x40, 0x00, 0x00, 0x16, //V.M.P(1), LEN(3) = 22 + padding
	'o', 'r', 'i', 'g',
	'.', 'r', 'e', 'a',
	'l', 'm', '.', 'n',
	'e', 't',   0,   0,
};

uint8_t const dwa_unexp[] = {
	0x01, 0x00, 0x00, 88, //VER(1), LEN(3)
	0x00, 0x00, 0x01, 0x18, //R.P.E.T(1), CMD(3) = 280
	0x00, 0x00, 0x00, 0x00, //APP-ID
	0x22, 0x22, 0x22, 0x22, //H2H-ID
	0x55, 0x55, 0x55, 0x55, //E2E-ID

	0x00, 0x00, 0x01, 0x0C, //AVP = 268 Result Code
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x00, 0x00, 0x0B, 0xBC, //result = 3004

	//NOTE: this AVP is not expected in DWA
	0x00, 0x00, 0x01, 0x02, //AVP-CODE = 258 Auth-App-Id AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x01, 0x00, 0x00, 0x16, //id = Gx

	0x00, 0x00, 0x01, 0x08, //AVP-CODE = 264 OrigHost
	0x40, 0x00, 0x00, 0x11, //V.M.P(1), LEN(3) = 17 + padding
	'O', 'r', 'i', 'g',
	'.', 'H', 'o', 's',
	't',   0,   0,   0,

	0x00, 0x00, 0x01, 0x28, //AVP-CODE = 296 OrigRealm
	0x40, 0x00, 0x00, 0x16, //V.M.P(1), LEN(3) = 22 + padding
	'o', 'r', 'i', 'g',
	'.', 'r', 'e', 'a',
	'l', 'm', '.', 'n',
	'e', 't',   0,   0,
};

uint8_t const ip4[] = {0x01,0x02,0x03,0x04};

TEST(encode, cer)
{
	diameter::base dia;

	//mandatory only
	diameter::CER& msg = dia.select();

	dia.header().ap_id(0);
	dia.header().hop_id(0x22222222);
	dia.header().end_id(0x55555555);

	std::size_t alloc_buf[1024];
	med::allocator alloc{alloc_buf};

	msg.ref<diameter::origin_host>().set("Orig.Host"sv);
	msg.ref<diameter::origin_realm>().set("orig.realm.net"sv);
	msg.ref<diameter::host_ip_address>().push_back(alloc)->set(sizeof(ip4), ip4);
	msg.ref<diameter::vendor_id>().set(diameter::VENDOR::NONE);
	msg.ref<diameter::product_name>().set("base:dia"sv);

	msg.ref<diameter::supported_vendor_id>().push_back(alloc)->set(diameter::VENDOR::TGPP);
	msg.ref<diameter::supported_vendor_id>().push_back(alloc)->set(diameter::VENDOR::NOKIA);
	msg.ref<diameter::auth_application_id>().push_back(alloc)->set(diameter::APPLICATION::NONE);
	msg.ref<diameter::auth_application_id>().push_back(alloc)->set(diameter::APPLICATION::S6A);
	msg.ref<diameter::auth_application_id>().push_back(alloc)->set(diameter::APPLICATION::GX);
	msg.ref<diameter::auth_application_id>().push_back(alloc)->set(diameter::APPLICATION::GXX);

	{
		auto* id = msg.ref<diameter::vendor_specific_application_id>().push_back(alloc);
		id->ref<diameter::vendor_id>().push_back(alloc)->set(diameter::VENDOR::TGPP);
		id->ref<diameter::auth_application_id>().set(diameter::APPLICATION::S6A);
	}
	{
		auto* id = msg.ref<diameter::vendor_specific_application_id>().push_back(alloc);
		id->ref<diameter::vendor_id>().push_back(alloc)->set(diameter::VENDOR::TGPP);
		id->ref<diameter::auth_application_id>().set(diameter::APPLICATION::GX);
	}
	{
		auto* id = msg.ref<diameter::vendor_specific_application_id>().push_back(alloc);
		id->ref<diameter::vendor_id>().push_back(alloc)->set(diameter::VENDOR::TGPP);
		id->ref<diameter::auth_application_id>().set(diameter::APPLICATION::GXX);
	}

	uint8_t buffer[1024];
	med::encoder_context<> ctx{buffer};
	encode(med::octet_encoder{ctx}, dia);
	EXPECT_EQ(sizeof(cer_encoded1), ctx.buffer().get_offset());
	EXPECT_TRUE(Matches(cer_encoded1, buffer));
}

TEST(decode, cer)
{
	diameter::base dia;

	std::size_t alloc_buf[1024];
	med::allocator alloc{alloc_buf};
	med::decoder_context<med::allocator> ctx{ cer_encoded1, &alloc};
	decode(med::octet_decoder{ctx}, dia);

	ASSERT_EQ(0, dia.header().ap_id());
	ASSERT_EQ(0x22222222, dia.header().hop_id());
	ASSERT_EQ(0x55555555, dia.header().end_id());

	diameter::CER const* msg = dia.cselect();
	ASSERT_NE(nullptr, msg);
	{
		auto const& host = msg->get<diameter::origin_host>();
		auto const exp = "Orig.Host"sv;
		EXPECT_TRUE(Matches(exp, host));
	}
	{
		auto const& realm = msg->get<diameter::origin_realm>();
		auto const exp = "orig.realm.net"sv;
		EXPECT_TRUE(Matches(exp, realm));
	}

	{
		uint8_t const exp[] = {0,1, 1,2,3,4};
		ASSERT_EQ(1, msg->count<diameter::host_ip_address>());
		for (auto& c : msg->get<diameter::host_ip_address>())
		{
			EXPECT_TRUE(Matches(exp, c.data()));
		}
	}

	EXPECT_EQ(diameter::VENDOR::NONE, msg->get<diameter::vendor_id>().get());
	{
		auto const& name = msg->get<diameter::product_name>();
		auto const exp = "base:dia"sv;
		EXPECT_TRUE(Matches(exp, name));
	}

	EXPECT_EQ(nullptr, msg->get<diameter::origin_state_id>());

	{
		diameter::VENDOR const exp[] = {diameter::VENDOR::TGPP, diameter::VENDOR::NOKIA};
		ASSERT_EQ(std::size(exp), msg->count<diameter::supported_vendor_id>());
		auto const* pexp = exp;
		for (auto const& v : msg->get<diameter::supported_vendor_id>())
		{
			EXPECT_EQ(*pexp, v.get());
			++pexp;
		}
	}

	{
		diameter::APPLICATION const ids[] = {diameter::APPLICATION::NONE, diameter::APPLICATION::S6A, diameter::APPLICATION::GX, diameter::APPLICATION::GXX};
		auto* exp = ids;
		ASSERT_EQ(std::size(ids), msg->count<diameter::auth_application_id>());
		for (auto& id : msg->get<diameter::auth_application_id>())
		{
			EXPECT_EQ(*exp, id.get());
			++exp;
		}
	}
	{
		std::pair<diameter::VENDOR, diameter::APPLICATION> const ids[] = {
			{diameter::VENDOR::TGPP, diameter::APPLICATION::S6A},
			{diameter::VENDOR::TGPP, diameter::APPLICATION::GX},
			{diameter::VENDOR::TGPP, diameter::APPLICATION::GXX},
		};
		auto* exp = ids;
		ASSERT_EQ(std::size(ids), msg->count<diameter::vendor_specific_application_id>());
		for (auto& v : msg->get<diameter::vendor_specific_application_id>())
		{
			ASSERT_EQ(1, v.count<diameter::vendor_id>());
			EXPECT_EQ(exp->first,  v.get<diameter::vendor_id>().begin()->get());
			EXPECT_EQ(exp->second, v.get<diameter::auth_application_id>()->get());
			++exp;
		}
	}
}

#if 1
TEST(encode, cea)
{
	diameter::base dia;

	//mandatory only
	diameter::CEA& msg = dia.select();

	dia.header().ap_id(0);
	dia.header().hop_id(0x22222222);
	dia.header().end_id(0x55555555);

	std::size_t alloc_buf[1024];
	med::allocator alloc{alloc_buf};

	msg.ref<diameter::result_code>().set(diameter::RESULT::SUCCESS);
	msg.ref<diameter::origin_host>().set("Orig.Host"sv);
	msg.ref<diameter::origin_realm>().set("orig.realm.net"sv);
	msg.ref<diameter::host_ip_address>().push_back(alloc)->set(sizeof(ip4), ip4);
	msg.ref<diameter::vendor_id>().set(diameter::VENDOR::NONE);
	msg.ref<diameter::product_name>().set("base:dia"sv);
	//msg.ref<diameter::origin_state_id>().set(0);
	msg.ref<diameter::supported_vendor_id>().push_back(alloc)->set(diameter::VENDOR::TGPP);
	msg.ref<diameter::supported_vendor_id>().push_back(alloc)->set(diameter::VENDOR::NOKIA);
	msg.ref<diameter::auth_application_id>().push_back(alloc)->set(diameter::APPLICATION::NONE);
	msg.ref<diameter::auth_application_id>().push_back(alloc)->set(diameter::APPLICATION::S6A);
	msg.ref<diameter::auth_application_id>().push_back(alloc)->set(diameter::APPLICATION::GX);
	msg.ref<diameter::auth_application_id>().push_back(alloc)->set(diameter::APPLICATION::GXX);

	{
		auto* id = msg.ref<diameter::vendor_specific_application_id>().push_back(alloc);
		id->ref<diameter::vendor_id>().push_back(alloc)->set(diameter::VENDOR::TGPP);
		id->ref<diameter::auth_application_id>().set(diameter::APPLICATION::S6A);
	}
	{
		auto* id = msg.ref<diameter::vendor_specific_application_id>().push_back(alloc);
		id->ref<diameter::vendor_id>().push_back(alloc)->set(diameter::VENDOR::TGPP);
		id->ref<diameter::auth_application_id>().set(diameter::APPLICATION::GX);
	}
	{
		auto* id = msg.ref<diameter::vendor_specific_application_id>().push_back(alloc);
		id->ref<diameter::vendor_id>().push_back(alloc)->set(diameter::VENDOR::TGPP);
		id->ref<diameter::auth_application_id>().set(diameter::APPLICATION::GXX);
	}

	uint8_t buffer[1024];
	med::encoder_context<> ctx{ buffer };
	encode(med::octet_encoder{ctx}, dia);
	ASSERT_EQ(sizeof(cea_encoded1), ctx.buffer().get_offset());
	EXPECT_TRUE(Matches(cea_encoded1, buffer));
}

TEST(decode, cea)
{
	std::size_t alloc_buf[1024];
	med::allocator alloc{alloc_buf};
	med::decoder_context<med::allocator> ctx{ cea_encoded1, &alloc};

	diameter::base dia;
	decode(med::octet_decoder{ctx}, dia);

	EXPECT_EQ(0, dia.header().ap_id());
	EXPECT_EQ(0x22222222, dia.header().hop_id());
	EXPECT_EQ(0x55555555, dia.header().end_id());

	diameter::CEA const* msg = dia.cselect();
	ASSERT_NE(nullptr, msg);

	EXPECT_EQ(diameter::RESULT::SUCCESS, msg->get<diameter::result_code>().get());
	{
		auto const& host = msg->get<diameter::origin_host>();
		auto const exp = "Orig.Host"sv;
		EXPECT_TRUE(Matches(exp, host));
	}
	{
		auto const& realm = msg->get<diameter::origin_realm>();
		auto const exp = "orig.realm.net"sv;
		EXPECT_TRUE(Matches(exp, realm));
	}

	{
		uint8_t const exp[] = {0,1, 1,2,3,4};
		ASSERT_EQ(1, msg->count<diameter::host_ip_address>());
		for (auto& c : msg->get<diameter::host_ip_address>())
		{
			EXPECT_TRUE(Matches(exp, c));
		}
	}

	EXPECT_EQ(diameter::VENDOR::NONE, msg->get<diameter::vendor_id>().get());
	{
		auto const& name = msg->get<diameter::product_name>();
		auto const exp = "base:dia"sv;
		EXPECT_TRUE(Matches(exp, name));
	}

	EXPECT_EQ(nullptr, msg->get<diameter::origin_state_id>());

	{
		diameter::VENDOR const exp[] = {diameter::VENDOR::TGPP, diameter::VENDOR::NOKIA};
		ASSERT_EQ(std::size(exp), msg->count<diameter::supported_vendor_id>());
		auto const* pexp = exp;
		for (auto const& v : msg->get<diameter::supported_vendor_id>())
		{
			EXPECT_EQ(*pexp, v.get());
			++pexp;
		}
	}

	{
		diameter::APPLICATION const ids[] = {diameter::APPLICATION::NONE, diameter::APPLICATION::S6A, diameter::APPLICATION::GX, diameter::APPLICATION::GXX};
		auto* exp = ids;
		ASSERT_EQ(std::size(ids), msg->count<diameter::auth_application_id>());
		for (auto& id : msg->get<diameter::auth_application_id>())
		{
			EXPECT_EQ(*exp, id.get());
			++exp;
		}
	}
	{
		std::pair<diameter::VENDOR, diameter::APPLICATION> const ids[] = {
			{diameter::VENDOR::TGPP, diameter::APPLICATION::S6A},
			{diameter::VENDOR::TGPP, diameter::APPLICATION::GX},
			{diameter::VENDOR::TGPP, diameter::APPLICATION::GXX},
		};
		auto* exp = ids;
		ASSERT_EQ(std::size(ids), msg->count<diameter::vendor_specific_application_id>());
		for (auto& id : msg->get<diameter::vendor_specific_application_id>())
		{
			ASSERT_EQ(1, id.count<diameter::vendor_id>());
			EXPECT_EQ(exp->first,  id.get<diameter::vendor_id>().begin()->get());
			EXPECT_EQ(exp->second, id.get<diameter::auth_application_id>()->get());
			++exp;
		}
	}
}

TEST(encode, dpr)
{
	diameter::base dia;

	//mandatory only
	diameter::DPR& msg = dia.select();

	dia.header().ap_id(0);
	dia.header().hop_id(0x22222222);
	dia.header().end_id(0x55555555);

	uint8_t buffer[1024] = {};
	med::encoder_context<> ctx{ buffer };

	msg.ref<diameter::origin_host>().set("Orig.Host"sv);
	msg.ref<diameter::origin_realm>().set("orig.realm.net"sv);
	msg.ref<diameter::disconnect_cause>().set(diameter::DISCONNECT_CAUSE::DO_NOT_WANT_TO_TALK_TO_YOU);

	encode(med::octet_encoder{ctx}, dia);
	ASSERT_EQ(sizeof(dpr_encoded1), ctx.buffer().get_offset());
	EXPECT_TRUE(Matches(dpr_encoded1, buffer));
}

TEST(decode, dpr)
{
	diameter::base dia;

	med::decoder_context<> ctx{ dpr_encoded1 };
	decode(med::octet_decoder{ctx}, dia);

	EXPECT_EQ(0, dia.header().ap_id());
	EXPECT_EQ(0x22222222, dia.header().hop_id());
	EXPECT_EQ(0x55555555, dia.header().end_id());

	diameter::DPR const* msg = dia.cselect();
	ASSERT_NE(nullptr, msg);

	{
		auto const& host = msg->get<diameter::origin_host>();
		auto const exp = "Orig.Host"sv;
		EXPECT_TRUE(Matches(exp, host));
	}
	{
		auto const& realm = msg->get<diameter::origin_realm>();
		auto const exp = "orig.realm.net"sv;
		EXPECT_TRUE(Matches(exp, realm));
	}

	EXPECT_EQ(diameter::DISCONNECT_CAUSE::DO_NOT_WANT_TO_TALK_TO_YOU, msg->get<diameter::disconnect_cause>().get());
}

TEST(encode, dpa)
{
	diameter::base dia;

	//mandatory only
	diameter::DPA& msg = dia.select();

	dia.header().ap_id(0);
	dia.header().hop_id(0x22222222);
	dia.header().end_id(0x55555555);

	uint8_t buffer[1024] = {};
	med::encoder_context<> ctx{ buffer };

	msg.ref<diameter::result_code>().set(diameter::RESULT::TOO_BUSY);
	msg.ref<diameter::origin_host>().set("Orig.Host"sv);
	msg.ref<diameter::origin_realm>().set("orig.realm.net"sv);

	encode(med::octet_encoder{ctx}, dia);
	ASSERT_EQ(sizeof(dpa_encoded1), ctx.buffer().get_offset());
	EXPECT_TRUE(Matches(dpa_encoded1, buffer));
}

TEST(decode, dpa)
{
	diameter::base dia;

	med::decoder_context<> ctx{ dpa_encoded1 };
	decode(med::octet_decoder{ctx}, dia);

	EXPECT_EQ(0, dia.header().ap_id());
	EXPECT_EQ(0x22222222, dia.header().hop_id());
	EXPECT_EQ(0x55555555, dia.header().end_id());

	diameter::DPA const* msg = dia.cselect();
	ASSERT_NE(nullptr, msg);

	EXPECT_EQ(diameter::RESULT::TOO_BUSY, msg->get<diameter::result_code>().get());
	{
		auto const& host = msg->get<diameter::origin_host>();
		auto const exp = "Orig.Host"sv;
		EXPECT_TRUE(Matches(exp, host));
	}
	{
		auto const& realm = msg->get<diameter::origin_realm>();
		auto const exp = "orig.realm.net"sv;
		EXPECT_TRUE(Matches(exp, realm));
	}
}

TEST(encode, dwr)
{
	diameter::base dia;

	//mandatory only
	diameter::DWR& msg = dia.select();

	dia.header().ap_id(0);
	dia.header().hop_id(0x22222222);
	dia.header().end_id(0x55555555);

	uint8_t buffer[1024] = {};
	med::encoder_context<> ctx{ buffer };

	msg.ref<diameter::origin_host>().set("Orig.Host"sv);
	msg.ref<diameter::origin_realm>().set("orig.realm.net"sv);
	//msg.ref<diameter::origin_state_id>().set(2);

	encode(med::octet_encoder{ctx}, dia);
	ASSERT_EQ(sizeof(dwr_encoded1), ctx.buffer().get_offset());
	EXPECT_TRUE(Matches(dwr_encoded1, buffer));
}

TEST(decode, dwr)
{
	diameter::base dia;

	med::decoder_context<> ctx{ dwr_encoded1 };
	decode(med::octet_decoder{ctx}, dia);

	EXPECT_EQ(0, dia.header().ap_id());
	EXPECT_EQ(0x22222222, dia.header().hop_id());
	EXPECT_EQ(0x55555555, dia.header().end_id());

	diameter::DWR const* msg = dia.cselect();
	ASSERT_NE(nullptr, msg);

	{
		auto const& host = msg->get<diameter::origin_host>();
		auto const exp = "Orig.Host"sv;
		EXPECT_TRUE(Matches(exp, host));
	}
	{
		auto const& realm = msg->get<diameter::origin_realm>();
		auto const exp = "orig.realm.net"sv;
		EXPECT_TRUE(Matches(exp, realm));
	}
}

TEST(encode, dwa)
{
	diameter::base dia;

	//mandatory only
	diameter::DWA& msg = dia.select();

	dia.header().ap_id(0);
	dia.header().hop_id(0x22222222);
	dia.header().end_id(0x55555555);

	uint8_t buffer[1024] = {};
	med::encoder_context<> ctx{ buffer };

	msg.ref<diameter::result_code>().set(diameter::RESULT::TOO_BUSY);
	msg.ref<diameter::origin_host>().set("Orig.Host"sv);
	msg.ref<diameter::origin_realm>().set("orig.realm.net"sv);

	encode(med::octet_encoder{ctx}, dia);
	ASSERT_EQ(sizeof(dwa_encoded1), ctx.buffer().get_offset());
	EXPECT_TRUE(Matches(dwa_encoded1, buffer));
}

TEST(decode, dwa)
{
	diameter::base dia;

	med::decoder_context<> ctx{ dwa_encoded1 };
	decode(med::octet_decoder{ctx}, dia);

	EXPECT_EQ(0, dia.header().ap_id());
	EXPECT_EQ(0x22222222, dia.header().hop_id());
	EXPECT_EQ(0x55555555, dia.header().end_id());

	diameter::DWA const* msg = dia.cselect();
	ASSERT_NE(nullptr, msg);

	EXPECT_EQ(diameter::RESULT::TOO_BUSY, msg->get<diameter::result_code>().get());
	{
		auto const& host = msg->get<diameter::origin_host>();
		auto const exp = "Orig.Host"sv;
		EXPECT_TRUE(Matches(exp, host));
	}
	{
		auto const& realm = msg->get<diameter::origin_realm>();
		auto const exp = "orig.realm.net"sv;
		EXPECT_TRUE(Matches(exp, realm));
	}
}
#endif

#if 1
TEST(decode, dwa_unexp)
{
	diameter::base dia;

	med::decoder_context<> ctx{ dwa_unexp };
	decode(med::octet_decoder{ctx}, dia);

	ASSERT_EQ(0, dia.header().ap_id());
	ASSERT_EQ(0x22222222, dia.header().hop_id());
	ASSERT_EQ(0x55555555, dia.header().end_id());

	diameter::DWA const* msg = dia.cselect();
	ASSERT_NE(nullptr, msg);

	ASSERT_EQ(diameter::RESULT::TOO_BUSY, msg->get<diameter::result_code>().get());
	{
		auto const& host = msg->get<diameter::origin_host>();
		auto const exp = "Orig.Host"sv;
		EXPECT_TRUE(Matches(exp, host));
	}
	{
		auto const& realm = msg->get<diameter::origin_realm>();
		auto const exp = "orig.realm.net"sv;
		EXPECT_TRUE(Matches(exp, realm));
	}
}
#endif

#if 1
uint8_t const req_unknown[] = {
	0x01, 0x00, 0x00, 0x4C, //VER(1), LEN(3)
	0x80, 0x00, 0x11, 0x1A, //R.P.E.T(1), CMD(3) = ??
	0x00, 0x00, 0x00, 0x00, //APP-ID
	0x22, 0x22, 0x22, 0x22, //H2H-ID
	0x55, 0x55, 0x55, 0x55, //E2E-ID

	0x00, 0x00, 0x01, 0x08, //AVP-CODE = 264 OrigHost
	0x40, 0x00, 0x00, 0x11, //V.M.P(1), LEN(3) = 17 + padding
	'O', 'r', 'i', 'g',
	'.', 'H', 'o', 's',
	't',   0,   0,   0,

	0x00, 0x00, 0x01, 0x28, //AVP-CODE = 296 OrigRealm
	0x40, 0x00, 0x00, 0x16, //V.M.P(1), LEN(3) = 22 + padding
	'o', 'r', 'i', 'g',
	'.', 'r', 'e', 'a',
	'l', 'm', '.', 'n',
	'e', 't',   0,   0,

	0x00, 0x00, 0x01, 0x11, //AVP = 273 Disconnect-Cause AVP
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x00, 0x00, 0x00, 0x02, //cause = 2
};
TEST(decode, req_unknown)
{
	diameter::base dia;

	med::decoder_context<> ctx{ req_unknown};
	decode(med::octet_decoder{ctx}, dia);

	ASSERT_EQ(0, dia.header().ap_id());
	ASSERT_EQ(0x22222222, dia.header().hop_id());
	ASSERT_EQ(0x55555555, dia.header().end_id());

	diameter::Request const* msg = dia.cselect();
	ASSERT_NE(nullptr, msg);

	auto* realm = msg->get<diameter::origin_realm>();
	ASSERT_NE(nullptr, realm);
	auto const exp = "orig.realm.net"sv;
	EXPECT_TRUE(Matches(exp, *realm));
}

uint8_t const ans_unknown[] = {
	0x01, 0x00, 0x00, 0x4C, //VER(1), LEN(3)
	0x00, 0x00, 0x11, 0x1A, //R.P.E.T(1), CMD(3) = ??
	0x00, 0x00, 0x00, 0x00, //APP-ID
	0x22, 0x22, 0x22, 0x22, //H2H-ID
	0x55, 0x55, 0x55, 0x55, //E2E-ID

	0x00, 0x00, 0x01, 0x0C, //AVP = 268 Result Code
	0x40, 0x00, 0x00, 0x0C, //V.M.P(1), LEN(3) = 12
	0x00, 0x00, 0x0B, 0xBC, //result = 3004

	0x00, 0x00, 0x01, 0x08, //AVP-CODE = 264 OrigHost
	0x40, 0x00, 0x00, 0x11, //V.M.P(1), LEN(3) = 17 + padding
	'O', 'r', 'i', 'g',
	'.', 'H', 'o', 's',
	't',   0,   0,   0,

	0x00, 0x00, 0x01, 0x28, //AVP-CODE = 296 OrigRealm
	0x40, 0x00, 0x00, 0x16, //V.M.P(1), LEN(3) = 22 + padding
	'o', 'r', 'i', 'g',
	'.', 'r', 'e', 'a',
	'l', 'm', '.', 'n',
	'e', 't',   0,   0,
};
TEST(decode, ans_unknown)
{
	diameter::base dia;

	med::decoder_context<> ctx{ ans_unknown};
	decode(med::octet_decoder{ctx}, dia);

	ASSERT_EQ(0, dia.header().ap_id());
	ASSERT_EQ(0x22222222, dia.header().hop_id());
	ASSERT_EQ(0x55555555, dia.header().end_id());

	diameter::Answer const* msg = dia.cselect();
	ASSERT_NE(nullptr, msg);

	auto* realm = msg->get<diameter::origin_realm>();
	ASSERT_NE(nullptr, realm);
	auto const exp = "orig.realm.net"sv;
	EXPECT_TRUE(Matches(exp, *realm));
}
#endif

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
