# Prints the compile flags (-D USE_* etc.) libreswan's own build uses, so the harnesses are
# compiled with the same struct layouts as libswan.a. Usage: make -s -C mayhem/harnesses -f flags.mk <vars> print-cflags
include ../../mk/dirs.mk
include $(top_srcdir)/mk/config.mk
print-cflags:
	@echo $(USERLAND_INCLUDES) $(USERLAND_CFLAGS)
print-ldflags:
	@echo $(USERLAND_LDFLAGS) $(NSS_LDFLAGS) $(NSPR_LDFLAGS)
