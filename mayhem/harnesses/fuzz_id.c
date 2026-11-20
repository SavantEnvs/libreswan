/* Identity strings: ttoid() incl. atodn() (lib/libswan/id.c, x509dn.c) — @fqdn, @#hex,
 * @~base64, @[keyid], addresses and text DNs (leftid=/rightid=), then formatting. */
#include "fuzz_common.h"
#include "id.h"
#include "diag.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz_logger_nss();
	char *str = fuzz_strdup(data, size);
	struct id id;
	diag_t d = ttoid(str, &id);
	if (d == NULL) {
		id_buf b;
		str_id(&id, &b);
		id_has_wildcards(&id);
		same_id(&id, &id);
		free_id_content(&id);
	} else {
		pfree_diag(&d);
	}
	free(str);
	return 0;
}
