/* Raw public keys (SubjectPublicKeyInfo DER, as given by leftpubkey= / DNS IPSECKEY):
 * pubkey_der_to_pubkey_content() (lib/libswan/pubkey_der_to_pubkey_content.c and the
 * RSA/ECDSA/EdDSA pubkey_type extractors, keyid/ckaid computation). */
#include "fuzz_common.h"
#include "secrets.h"
#include "diag.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct logger *logger = fuzz_logger_nss();
	uint8_t *copy = malloc(size ? size : 1);
	memcpy(copy, data, size);
	struct pubkey_content pkc = {0};
	diag_t d = pubkey_der_to_pubkey_content(shunk2(copy, size), &pkc);
	if (d == NULL) {
		free_pubkey_content(&pkc, logger);
	} else {
		pfree_diag(&d);
	}
	free(copy);
	return 0;
}
