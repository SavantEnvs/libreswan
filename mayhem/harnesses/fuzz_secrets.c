/* ipsec.secrets parser: lsw_load_preshared_secrets() (lib/libswan/secrets.c + lex.c:
 * PSK / XAUTH / PPK / RSA / ECDSA records, ids, quoting, include). */
#include "fuzz_common.h"
#include "secrets.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct logger *logger = fuzz_logger_nss();
	char path[512];
	if (fuzz_tmpfile(data, size, path, sizeof(path)) != 0)
		return 0;
	struct secret *secrets = NULL;
	lsw_load_preshared_secrets(&secrets, path, logger);
	lsw_free_preshared_secrets(&secrets, logger);
	unlink(path);
	return 0;
}
