/* IP text parsers (lib/libswan/ip/): addresses, subnets, ranges, CIDRs, selectors, pools,
 * protoports and SAIDs as written in ipsec.conf / whack. Byte 0 picks the parser and the
 * address family; the rest is the text; a successful parse is formatted back. */
#include "fuzz_common.h"
#include "diag.h"
#include "ip_info.h"
#include "ip_address.h"
#include "ip_subnet.h"
#include "ip_range.h"
#include "ip_cidr.h"
#include "ip_selector.h"
#include "ip_pool.h"
#include "ip_protoport.h"
#include "ip_said.h"

#define DONE(D) do { diag_t d_ = (D); if (d_ != NULL) { pfree_diag(&d_); goto out; } } while (0)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1)
		return -1;
	fuzz_logger();
	uint8_t sel = data[0];
	const struct ip_info *afi = ((sel >> 4) % 3 == 0) ? NULL :
		((sel >> 4) % 3 == 1) ? &ipv4_info : &ipv6_info;
	/* heap copy without a terminator: the parsers take shunk_t */
	uint8_t *copy = malloc(size - 1 ? size - 1 : 1);
	memcpy(copy, data + 1, size - 1);
	shunk_t in = shunk2(copy, size - 1);
	switch (sel % 11) {
	case 0: { ip_address a; DONE(ttoaddress_num(in, afi, &a)); address_buf b; str_address(&a, &b); break; }
	case 1: { ip_subnet s; ip_address nz; DONE(ttosubnet_num(in, afi, &s, &nz)); subnet_buf b; str_subnet(&s, &b); break; }
	case 2: { ip_range r; DONE(ttorange_num(in, afi, &r)); range_buf b; str_range(&r, &b); break; }
	case 3: { ip_cidr c; DONE(ttocidr_num(in, afi, &c)); cidr_buf b; str_cidr(&c, &b); break; }
	case 4: { ip_selector s; ip_address nz; DONE(ttoselector_num(in, afi, &s, &nz)); selector_buf b; str_selector(&s, &b); break; }
	case 5: { ip_pool p; DONE(ttopool_num(in, afi, &p)); pool_buf b; str_pool(&p, &b); break; }
	case 6: { ip_protoport pp; err_t e = ttoprotoport(in, &pp); if (e == NULL) { protoport_buf b; str_protoport(&pp, &b); } break; }
	case 7: { ip_said s; DONE(ttosaid(in, &s)); said_buf b; str_said(&s, &b); break; }
	case 8: { ip_subnets *ss = NULL; DONE(ttosubnets_num(in, afi, &ss)); char buf[4096]; struct jambuf j = ARRAY_AS_JAMBUF(buf); jam_subnets(&j, ss); pfreeany(ss); break; }
	case 9: { ip_selectors *ss = NULL; ip_address nz; DONE(ttoselectors_num(in, ", ", afi, &ss, &nz)); char buf[4096]; struct jambuf j = ARRAY_AS_JAMBUF(buf); jam_selectors(&j, ss); pfreeany(ss); break; }
	case 10: { ip_ranges *rr = NULL; DONE(ttoranges_num(in, afi, &rr)); pfreeany(rr); break; }
	}
out:
	free(copy);
	return 0;
}
