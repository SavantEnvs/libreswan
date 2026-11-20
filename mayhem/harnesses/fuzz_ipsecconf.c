/* ipsec.conf parser: confread_load() (lib/libswan/ipsecconf: flex/bison parser, keyword
 * value parsers, also=/include handling, %default merge). */
#include "fuzz_common.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/setup.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct logger *logger = fuzz_logger();
	char path[512];
	if (fuzz_tmpfile(data, size, path, sizeof(path)) != 0)
		return 0;
	struct starter_config *cfg = confread_load(path, false, logger, 0);
	if (cfg != NULL)
		confread_free(cfg);
	free_config_setup();	/* config setup is process-global; reset per input */
	unlink(path);
	return 0;
}
