/* Text decoders (lib/libswan): ttodata()/ttochunk() hex/base64/text with 0x/0s/0t
 * prefixes, ttodeltatime()/ttodeltatimescale(), ttorealtime(); results formatted back
 * with datatot()/str_deltatime()/str_realtime(). Byte 0 selects the function. */
#include "fuzz_common.h"
#include "diag.h"
#include "ttodata.h"
#include "deltatime.h"
#include "realtime.h"
#include "timescale.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1)
		return -1;
	fuzz_logger();
	uint8_t sel = data[0];
	char *str = fuzz_strdup(data + 1, size - 1);
	shunk_t in = shunk2(str, size - 1);
	static const int bases[] = { 0, 16, 64, 256 };
	switch (sel % 5) {
	case 0: {
		char out[256];
		size_t needed = 0;
		if (ttodata(in, bases[(sel >> 3) & 3], out, sizeof(out), &needed) == NULL) {
			char txt[1024];
			datatot(out, needed < sizeof(out) ? needed : sizeof(out), "x16s"[(sel >> 5) & 3], txt, sizeof(txt));
		}
		break;
	}
	case 1: {
		chunk_t c = empty_chunk;
		if (ttochunk(in, bases[(sel >> 3) & 3], &c) == NULL)
			free_chunk_content(&c);
		break;
	}
	case 2: {
		deltatime_t dt;
		diag_t d = ttodeltatime(in, &dt);
		if (d == NULL) { deltatime_buf b; str_deltatime(dt, &b); } else pfree_diag(&d);
		break;
	}
	case 3: {
		deltatime_t dt;
		enum timescale ts = (enum timescale)((sel >> 3) % (TIMESCALE_WEEKS + 1));
		diag_t d = ttodeltatimescale(in, &dt, ts);
		if (d == NULL) { deltatime_buf b; str_deltatime_scaled(dt, ts, &b); } else pfree_diag(&d);
		break;
	}
	case 4: {
		realtime_t rt;
		diag_t d = ttorealtime(str, &rt);
		if (d == NULL) { realtime_buf b; str_realtime(rt, true, &b); } else pfree_diag(&d);
		break;
	}
	}
	free(str);
	return 0;
}
