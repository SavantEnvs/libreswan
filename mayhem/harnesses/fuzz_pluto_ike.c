/* pluto's IKE datagram entry: process_md() (programs/pluto/demux.c) on a message received from
 * the network: ISAKMP header and payload decode (packet.c), the IKEv1 / IKEv2 demux, and the
 * responder's handling of an IKE_SA_INIT / Main Mode / Aggressive Mode request (connection
 * lookup, SA proposal selection, KE, Nonce, NAT-D, ID, vendor IDs, cookies, notifies) up to the
 * reply. Links all of pluto's objects except plutomain.o (the daemon's main(): option parsing,
 * forking, the event loop); the three small functions other objects take from it are defined
 * below. Init follows plutomain.c's main() without the kernel netlink sockets, control socket
 * and listening sockets. The input is one UDP payload as udp_read_packet() hands it to alloc_md()
 * after reading it from the socket, from peer 127.0.0.1:500 to the lo endpoint 127.0.0.1:500.
 *
 * Configuration, as a pluto started with it would have: config setup ikev1-policy=accept,
 * listen-udp=no, listen-tcp=no; an ipsec.secrets with one PSK for any peer; and three
 * connections from any peer added as `ipsec add` adds them (IKEv2, IKEv1 Main Mode, IKEv1
 * Aggressive Mode, all authby=secret).
 *
 * Per input: the responder's crypto (KE, nonce) is queued on the event loop, as pluto does with
 * no helper threads; the harness runs the events that are due (event_base_loop(EVLOOP_NONBLOCK))
 * so the reply is built and sent, then deletes every state the input created (which also
 * deletes the connection instance) and runs the loop again to drop cancelled work.
 *
 * State kept across inputs, on purpose: the configuration above (not changed by a message), the
 * NSS / ike_alg / vendor-ID tables (read-only after init), the cookie secret (random per process,
 * read only in DDoS mode, which the half-open count never reaches since states are deleted), and
 * serial-number counters (state, instance and request numbers; only names and logs use them).
 * The log rate limiters are made unlimited (the `impair log-rate-limit` knob, set to UINT_MAX):
 * otherwise their counters, reset only by an hourly timer that never runs here, would silence
 * logging after 1000 inputs. Replies go to an unbound UDP socket (send errors are logged and
 * ignored, like a lost packet).
 *
 * The host's interfaces are not scanned: kernel_iface_linux.o (SIOCGIFCONF and
 * /proc/net/if_inet6) is not linked, and its two functions are defined below to report one
 * device, lo with 127.0.0.1, so the harness behaves the same in any sandbox. */
#define _GNU_SOURCE	/* memfd_create() */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <limits.h>
#include <event2/event.h>

#include "defs.h"
#include "log.h"
#include "names.h"
#include "lswnss.h"
#include "ike_alg.h"
#include "crypt_symkey.h"
#include "vendorid.h"
#include "demux.h"
#include "iface.h"
#include "state.h"
#include "state_db.h"
#include "connection_db.h"
#include "spd_db.h"
#include "ikev1_states.h"
#include "ikev2_states.h"
#include "ikev1_demux.h"
#include "server.h"
#include "log_limiter.h"
#include "ddos.h"
#include "global_redirect.h"
#include "ikev2_redirect.h"
#include "ip_info.h"
#include "ip_endpoint.h"
#include "impair.h"
#include "kernel.h"
#include "kernel_alg.h"
#include "keys.h"
#include "ikev2_ike_sa_init.h"
#include "ikev2_unsecured.h"
#include "whack.h"
#include "connections.h"
#include "extract.h"
#include "ipsecconf/conn.h"
#include "ipsecconf/setup.h"
#include "kernel_iface.h"

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static struct logger *logger;
static pthread_t main_thread;

/* From plutomain.c, which is not linked (see above). */
bool in_main_thread(void) { return pthread_equal(pthread_self(), main_thread); }
void free_pluto_main(void) { }
void show_setup_plutomain(struct show *s) { (void)s; }
static struct iface_endpoint *ifp;

/* From kernel_iface_linux.c, which is not linked (see above): the device list find_ifaces()
 * receives, as find_kernel_ifaces() builds it, fixed to lo 127.0.0.1 and no IPv6 device. */
struct kernel_iface *find_kernel_ifaces4(struct verbose verbose)
{
	(void)verbose;
	static const char name[] = "lo";
	struct kernel_iface *ri = overalloc_thing(struct kernel_iface, sizeof(name));
	ri->addr = ipv4_info.address.loopback;
	memcpy(ri->name, name, sizeof(name));
	ri->next = NULL;
	return ri;
}

struct kernel_iface *find_kernel_ifaces6(struct verbose verbose)
{
	(void)verbose;
	return NULL;
}

/* The connection whack_add() (whack_add.c) would add for
 *   ipsec add --name NAME left=127.0.0.1 right=%any authby=secret keyexchange=KE
 *             [aggressive=yes ike=...]   (aggressive mode needs an explicit ike=) */
static void add_fuzz_connection(const char *name, const char *keyexchange, const char *aggressive,
				const char *ike)
{
	struct whack_message wm;
	init_whack_message(&wm, WHACK_FROM_ADDCONN);
	wm.whack_command = WHACK_ADD;
	wm.name = name;
	wm.conn[END_ROOF].value[KWS_AUTHBY] = "secret";
	wm.conn[END_ROOF].value[KWS_KEYEXCHANGE] = keyexchange;
	wm.conn[END_ROOF].value[KWS_AGGRESSIVE] = aggressive;
	wm.conn[END_ROOF].value[KWS_IKE] = ike;
	wm.end[LEFT_END].conn->value[KWS_HOST] = "127.0.0.1";
	wm.end[RIGHT_END].conn->value[KWS_HOST] = "%any";

	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, NULL);
	struct host_addrs addrs = {0};
	diag_t d = host_addrs_from_whack_message(&wm, &addrs, verbose);
	if (d == NULL)
		d = add_connection(&wm, &addrs, logger);
	if (d != NULL) {
		fprintf(stderr, "fuzz: adding connection %s failed: %s\n", name, str_diag(d));
		abort();
	}
}

/* ipsec.secrets with one PSK for any peer, loaded the way pluto loads secrets on start-up
 * (load_preshared_secrets() reads config setup secretsfile=), so IKEv1 Main / Aggressive Mode
 * PSK proposals are accepted. The file goes to the first writable directory of $TMPDIR (when
 * set and non-empty), /tmp, /dev/shm, /var/tmp and the working directory, and is removed once
 * loaded; an anonymous memfd, read through /proc/self/fd, is the last resort. */
static void load_fuzz_psk(void)
{
	static const char secrets[] = "%any %any : PSK \"fuzz-pre-shared-key-0123456789\"\n";
	const size_t len = sizeof(secrets) - 1;
	const char *tmp = getenv("TMPDIR");
	const char *dirs[] = { (tmp != NULL && tmp[0] != '\0') ? tmp : "/tmp",
			       "/tmp", "/dev/shm", "/var/tmp", ".", };
	char path[4096];
	int fd = -1;
	bool unlink_path = true;
	for (size_t i = 0; fd < 0 && i < sizeof(dirs) / sizeof(dirs[0]); i++) {
		snprintf(path, sizeof(path), "%s/fuzz-pluto-secrets-XXXXXX", dirs[i]);
		fd = mkstemp(path);
		if (fd >= 0 && write(fd, secrets, len) != (ssize_t)len) {
			fprintf(stderr, "fuzz: write %s: %s\n", path, strerror(errno));
			close(fd);
			unlink(path);
			fd = -1;
		}
	}
	if (fd >= 0) {
		close(fd);
	} else {
		fd = memfd_create("fuzz-pluto-secrets", 0);
		if (fd < 0 || write(fd, secrets, len) != (ssize_t)len) {
			fprintf(stderr, "fuzz: no writable directory and memfd_create failed: %s\n",
				strerror(errno));
			abort();
		}
		snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
		unlink_path = false;	/* fd stays open: pluto re-reads secretsfile on reload */
	}
	update_setup_string(KSF_SECRETSFILE, path);
	load_preshared_secrets(logger);
	if (unlink_path)
		unlink(path);
}

/* Run the events that are due now (queued crypto, its continuation); timers in the future
 * (retransmits, the hourly log-limiter reset) are not reached. */
static void run_due_events(void)
{
	for (int i = 0; i < 4; i++)
		event_base_loop(get_pluto_event_base(), EVLOOP_NONBLOCK);
}

/* Delete every state (Child SAs first, they are newer) without sending deletes. */
static void delete_all_states(void)
{
	FOR_EACH_THING(want_child, true, false) {
		struct state_filter sf = {
			.search = { .order = NEW2OLD, .verbose.logger = logger, .where = HERE, },
		};
		while (next_state(&sf)) {
			bool is_child = (sf.st->st_clonedfrom != SOS_NOBODY);
			if (is_child != want_child)
				continue;
			if (is_child) {
				struct child_sa *child = pexpect_child_sa(sf.st);
				delete_child_sa(&child);
			} else {
				struct ike_sa *ike = pexpect_ike_sa(sf.st);
				delete_ike_sa(&ike);
			}
		}
	}
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	main_thread = pthread_self();
	logger = init_log("pluto");
	/* config setup ikev1-policy=accept (upstream's default is drop, which discards every
	 * IKEv1 packet before it is decoded); plutomain.c applies it before init_ikev1_demux() */
	update_setup_option(KBF_IKEv1_POLICY, GLOBAL_IKEv1_ACCEPT);
	/* the globals plutomain.c's main() takes from config setup (upstream defaults) */
	log_ip = config_setup_yn(KYN_LOGIP);
	pluto_uniqueIDs = config_setup_yn(KYN_UNIQUEIDS);
	pluto_drop_oppo_null = config_setup_yn(KYN_DROP_OPPO_NULL);
	pluto_ike_socket_errqueue = config_setup_yn(KYN_IKE_SOCKET_ERRQUEUE);
	ikev2_signature_hash_algorithms = config_setup_yna(KSF_SIGNATURE_HASH_ALGORITHMS);
	ikev2_ike_sa_init_full_transcript_auth = config_setup_yna(KSF_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	init_ddos(logger);
	/* plutomain.c sets this from config setup; global-redirect=no is its default */
	init_global_redirect(GLOBAL_REDIRECT_NO, NULL, logger);
	init_names();
	init_ikev1_states(logger);
	init_ikev2_states(logger);
	init_states();
	state_db_init(logger);
	connection_db_init(logger);
	spd_db_init(logger);
	init_nss(NULL, (struct nss_flags){0}, logger);
	init_ikev1_demux(logger);
	init_crypt_symkey(logger);
	init_server(logger);
	init_log_limiter(logger);
	init_ike_alg(logger);
	init_vendorid(logger);
	/* see the comment at the top: no input may change the rate limiters' outcome */
	impair.log_rate_limit = (struct impair_unsigned){ .enabled = true, .value = UINT_MAX, };

	/* plutomain.c's default kernel stack (XFRM); its limits are read when a connection is
	 * added. init_kernel() (netlink sockets) is not run: nothing an unauthenticated message
	 * reaches installs kernel state. */
	kernel_ops = kernel_stacks[0];

	/* Interfaces: config setup listen-udp=no listen-tcp=no, then pluto's own interface pass
	 * (find_ifaces(), as on start-up and `ipsec listen`), which records the devices that
	 * find_kernel_ifaces4/6() above report (lo 127.0.0.1) without binding any socket.
	 * Connections orient against them. */
	update_setup_yn(KYN_LISTEN_UDP, YN_NO);
	update_setup_yn(KYN_LISTEN_TCP, YN_NO);
	init_ifaces(logger);
	find_ifaces(false, logger);

	/* One IKE endpoint, 127.0.0.1:500 on lo, the way bind_iface_endpoint() (iface.c)
	 * registers it, but with a socket that is not bound (replies are sent nowhere). */
	ip_address local = ipv4_info.address.loopback;
	struct iface_device *dev = find_iface_device_by_address(&local);
	if (dev == NULL) {
		fprintf(stderr, "fuzz: no interface with address 127.0.0.1\n");
		abort();
	}
	ip_endpoint local_endpoint =
		endpoint_from_address_protocol_port(local, &ip_protocol_udp, ip_hport(500));
	ifp = alloc_iface_endpoint(socket(AF_INET, SOCK_DGRAM, 0), dev, &udp_iface_io,
				   ESP_ENCAPSULATION_DISABLED, INITIATOR_PORT_FIXED,
				   local_endpoint, HERE);

	/* kernel_xfrm_init()'s algorithm registration ("just assume any algorithm with a
	 * NETLINK_XFRM name works"), without its netlink sockets; ESP proposals need it. */
	for (const struct encrypt_desc **algp = next_encrypt_desc(NULL);
	     algp != NULL; algp = next_encrypt_desc(algp)) {
		if ((*algp)->encrypt_netlink_xfrm_name != NULL)
			kernel_encrypt_add(*algp, logger);
	}
	for (const struct integ_desc **algp = next_integ_desc(NULL);
	     algp != NULL; algp = next_integ_desc(algp)) {
		if ((*algp)->integ_netlink_xfrm_name != NULL)
			kernel_integ_add(*algp, logger);
	}

	load_fuzz_psk();
	add_fuzz_connection("fuzz-ikev2", "ikev2", NULL, NULL);
	add_fuzz_connection("fuzz-ikev1-main", "ikev1", NULL, NULL);
	add_fuzz_connection("fuzz-ikev1-aggr", "ikev1", "yes", "aes128-sha2_256;modp2048");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	ip_address peer = ipv4_info.address.loopback;
	ip_endpoint sender = endpoint_from_address_protocol_port(peer, &ip_protocol_udp, ip_hport(500));
	struct msg_digest *md = alloc_md(ifp, sender, data, size, logger, HERE);
	process_md(md);
	md_delref(&md);
	run_due_events();
	delete_all_states();
	run_due_events();
	return 0;
}
