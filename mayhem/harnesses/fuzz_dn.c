/* DER distinguished names (lib/libswan/x509dn.c, asn1.c): the same code that handles a
 * peer's ID_DER_ASN1_DN. The input is split into two DNs at its midpoint (byte 0 shifts
 * the split); each is parsed and formatted, then the pair is compared and wildcard-matched. */
#include "fuzz_common.h"
#include "x509.h"
#include "asn1.h"

static void one(asn1_t dn)
{
	if (parse_dn(dn) != NULL)
		return;
	dn_buf b;
	str_dn(dn, &b);
	dn_has_wildcards(dn);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1)
		return -1;
	struct logger *logger = fuzz_logger_nss();
	size_t rest = size - 1;
	size_t split = rest ? (data[0] % (rest + 1)) : 0;
	/* separate heap copies so ASan sees the exact bounds of each DN */
	uint8_t *a = malloc(split ? split : 1), *b = malloc(rest - split ? rest - split : 1);
	memcpy(a, data + 1, split);
	memcpy(b, data + 1 + split, rest - split);
	asn1_t da = { .ptr = a, .len = split }, db = { .ptr = b, .len = rest - split };
	one(da);
	one(db);
	struct verbose verbose = { .logger = logger, .stream = NO_STREAM };
	if (parse_dn(da) == NULL && parse_dn(db) == NULL) {
		int wild = 0;
		same_dn(da, db, verbose);
		match_dn(da, db, &wild, verbose);
		wild = 0;
		match_dn_any_order_wild(da, db, &wild, verbose);
	}
	free(a);
	free(b);
	return 0;
}
