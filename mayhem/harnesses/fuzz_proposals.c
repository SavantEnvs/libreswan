/* ike=/esp=/ah= proposal parser: proposals_from_str() (lib/libswan/proposals.c,
 * v1_proposals.c, v2_proposals.c), driven exactly like programs/algparse/algparse.c.
 * Byte 0 picks the protocol, the IKE version and the pfs / ignore-lookup-error policy;
 * the rest is the proposal string. */
#include "fuzz_common.h"
#include "proposals.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1)
		return -1;
	struct logger *logger = fuzz_logger_nss();
	uint8_t sel = data[0];
	size_t nproto = 0;
	while (ike_alg_protocols[nproto] != NULL)
		nproto++;
	const struct ike_alg_protocol *protocol = ike_alg_protocols[sel % nproto];
	char *str = fuzz_strdup(data + 1, size - 1);
	struct proposal_policy policy = {
		.version = (sel & 0x10) ? IKEv1 : IKEv2,
		.alg_is_ok = protocol->alg_is_ok,
		.pfs = (sel & 0x20) != 0,
		.stream = WHACK_STREAM,
		.logger = logger,
		.check_pfs_vs_ke = protocol->pfs_vs_dh,
		.ignore_transform_lookup_error = (sel & 0x40) != 0,
	};
	struct proposal_parser *parser = protocol->parser(&policy);
	struct proposals *proposals = proposals_from_str(parser, (sel & 0x80) ? NULL : str);
	if (proposals != NULL) {
		FOR_EACH_PROPOSAL(proposals, proposal) {
			char string[LOG_WIDTH];
			struct jambuf buf = ARRAY_AS_JAMBUF(string);
			jam_proposal(&buf, proposal);
		}
		free_proposals(&proposals);
	}
	free_proposal_parser(&parser);
	free(str);
	return 0;
}
