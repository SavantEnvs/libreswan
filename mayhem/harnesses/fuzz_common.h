/* Shared one-time setup for the libswan fuzz harnesses (mayhem/ layer, not upstream). */
#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include "lswtool.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "lswnss.h"
#include "ike_alg.h"

/* A tool logger, like the testing/programs/*check tools use. */
static struct logger *fuzz_logger(void)
{
	static struct logger *logger;
	if (logger == NULL) {
		char *argv[] = { "fuzz", NULL };
		logger = tool_logger(1, argv);
	}
	return logger;
}

/* NSS without a database (init_nss falls back to NSS_NoDB_Init), then the algorithm tables,
 * the same sequence programs/algparse/algparse.c uses. Read-only state after this. */
static struct logger *fuzz_logger_nss(void)
{
	static bool done;
	struct logger *logger = fuzz_logger();
	if (!done) {
		init_nss(NULL, (struct nss_flags){0}, logger);
		init_ike_alg(logger);
		done = true;
	}
	return logger;
}

/* Copy the input into a NUL-terminated heap string (the text parsers take C strings). */
static char *fuzz_strdup(const uint8_t *data, size_t size)
{
	char *s = malloc(size + 1);
	memcpy(s, data, size);
	s[size] = '\0';
	return s;
}

/* Write the input to a fresh file under $TMPDIR for the file-reading parsers. */
static int fuzz_tmpfile(const uint8_t *data, size_t size, char *path, size_t pathlen)
{
	const char *tmp = getenv("TMPDIR");
	snprintf(path, pathlen, "%s/lswfuzzXXXXXX", (tmp && *tmp) ? tmp : "/tmp");
	int fd = mkstemp(path);
	if (fd < 0)
		return -1;
	size_t off = 0;
	while (off < size) {
		ssize_t w = write(fd, data + off, size - off);
		if (w <= 0) { close(fd); unlink(path); return -1; }
		off += (size_t)w;
	}
	close(fd);
	return 0;
}
#endif
