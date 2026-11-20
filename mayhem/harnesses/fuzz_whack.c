/* whack control-socket message deserializer: unpack_whack_msg() (lib/libswan/whack/pickle.c).
 * Mirrors pluto's whack_handle_1() (programs/pluto/rcv_whack.c): read up to
 * sizeof(struct whack_message) bytes into a zeroed message, then unpack it with n = bytes read.
 * Seeds (mayhem/fuzz-whack/testsuite) are messages as whack's pack_whack_msg() writes them:
 * `status` (WHACK_BASIC_MAGIC, stable) and an `add` and an `initiate`. The last two carry the
 * whack_magic() of the build they were made with (a checksum of the version string, so it
 * changes with every commit); libFuzzer's CMP feedback restores the 4-byte magic in seconds and
 * the rest of the message (string table, connection keywords) stays valid. */
#include "fuzz_common.h"
#include "whack.h"
#include "diag.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct logger *logger = fuzz_logger();
	struct whack_message *wm = calloc(1, sizeof(*wm));
	size_t n = size < sizeof(*wm) ? size : sizeof(*wm);
	if (n == 0) {	/* whack_handle_1() treats a 0-byte read as an error and stops */
		free(wm);
		return -1;
	}
	memcpy(wm, data, n);
	struct whackpacker wp = { .msg = wm, .n = n };
	diag_t d = unpack_whack_msg(&wp, logger);
	if (d != NULL)
		pfree_diag(&d);
	free(wm);
	return 0;
}
