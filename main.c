#include <sys/param.h>
#include <sys/cpuset.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <libutil.h>
#include <sys/sbuf.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#if DEBUG
#define D_LOG(...)	printf("%s(%d) %s:", __FILE__, __LINE__, __func__), printf(__VA_ARGS__)
#else
#define D_LOG(...)	;
#endif

struct nm_desc *nm_desc = NULL;
uint16_t new_mss4;
uint16_t new_mss6;
#if DEBUG
uint64_t pctr = 0;
uint64_t rctr = 0;
#endif
static uint64_t dctr = 0;

#define DROP_BUDGET 512

static uint64_t idle_loops = 0;
static uint64_t progress_watchdog = 0;
static struct timespec last_progress_ts = {0,0};
static inline long elapsed_ms_since(struct timespec *ts)
{
	struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
	return (long)((now.tv_sec - ts->tv_sec)*1000 + (now.tv_nsec - ts->tv_nsec)/1000000);
}

static inline u_int
sum_rx_avail(void)
{
	u_int total = 0;
	for (uint32_t i = nm_desc->first_rx_ring; i <= nm_desc->last_rx_ring; i++) {
		struct netmap_ring *rx = NETMAP_RXRING(nm_desc->nifp, i);
		total += nm_ring_space(rx);
	}
	return total;
}

static int
rewrite_tcpmss(char *tcp, uint16_t *new_mss)
{
	struct tcphdr* tcphdr;
	tcphdr = (struct tcphdr *)tcp;
	uint16_t chksum = ntohs((uint16_t)tcphdr->th_sum);
	uint16_t hdrlen = (uint16_t)tcphdr->th_off * 4;
	uint16_t h_new_mss = ntohs(*new_mss);
	D_LOG("chksum: %x\n", chksum);
	D_LOG("tcp hdr len: %u\n", hdrlen);

	char *tcpopt = tcp + sizeof(struct tcphdr);
	const char *tcpopt_end = tcp + hdrlen;
	while(tcpopt < tcpopt_end)
	{
		switch(*tcpopt)
		{
			case TCPOPT_MAXSEG:
				D_LOG("offset: %lu, option: MSS\n", tcpopt - tcp);
				if(*(tcpopt+1) != TCPOLEN_MAXSEG)
					return 0;

				uint16_t old_mss;
				memcpy(&old_mss, (tcpopt + 2), sizeof(old_mss));
				uint16_t h_old_mss = ntohs(old_mss);
				D_LOG("old mss: %u\n", h_old_mss);

				if(h_old_mss <= h_new_mss)
					return 0;

				memcpy(tcpopt + 2, new_mss, sizeof(*new_mss));
				D_LOG("new mss: %u\n", h_new_mss);

				uint32_t sum;
				sum = ~chksum - h_old_mss + h_new_mss;
				sum = (sum & 0xFFFF) + (sum >> 16);
				sum = (sum & 0xFFFF) + (sum >> 16);
				tcphdr->th_sum = htons(~sum);

				D_LOG("new chksum: %x\n", ntohs(tcphdr->th_sum));

#if DEBUG
				rctr++;
#endif
				return 1;
			case TCPOPT_NOP:
				D_LOG("offset: %lu, option: NOP\n", tcpopt - tcp);
				tcpopt += TCPOLEN_NOP;
				break;
			case TCPOPT_EOL:
				return 0;
			default:
				D_LOG("offset: %lu, option: %x, length: %u\n", tcpopt - tcp, *tcpopt, *(tcpopt + 1));
				if(*(tcpopt + 1) == 0)
				{
					D_LOG("Invalid TCP option length. Skip.\n");
					return 0;	//invalid TCP option length
				}
				tcpopt += *(tcpopt + 1);
		}
		D_LOG("next offset: %lu\n", tcpopt - tcp);
	}
	return 0;
}

static int
check_packet(int dir, void *buf, unsigned int len)
{
	char *payload;
	struct ether_header *ether;
	struct ip *ip;
	struct ip6_hdr *ip6;

	if(dir == 1) {
		return 0;
	}

	ether = (struct ether_header *)buf;

#if !defined NO_VLAN
	int no_tag = 0;
	do
	{
		D_LOG("ethertype: %x, length: %u\n", ntohs(ether->ether_type), len);
		switch(ether->ether_type)
		{
			case htons(ETHERTYPE_QINQ):
				D_LOG("802.1ad tag detected. tag: %u\n", ntohs(((struct ether_vlan_header *)ether)->evl_tag));
				// we don't use src/dst in ether header so just add offset.
				ether = (struct ether_header *)((char *)ether + ETHER_VLAN_ENCAP_LEN);
				break;
			case htons(ETHERTYPE_8021Q9100):
			case htons(ETHERTYPE_8021Q9200):
			case htons(ETHERTYPE_8021Q9300):
				D_LOG("802.1Q stacking tag detected. tag: %u\n", ntohs(((struct ether_vlan_header *)ether)->evl_tag));
				ether = (struct ether_header *)((char *)ether + ETHER_VLAN_ENCAP_LEN);
				break;
			case htons(ETHERTYPE_VLAN):
				D_LOG("802.1Q tag detected. tag: %u\n", ntohs(((struct ether_vlan_header *)ether)->evl_tag));
				ether = (struct ether_header *)((char *)ether + ETHER_VLAN_ENCAP_LEN);
				break;
			default:
				no_tag = 1;
		}
	}while(no_tag != 1);
#endif

	switch(ether->ether_type)
	{
		case htons(ETHERTYPE_IP):
			ip = (struct ip *)(ether + 1);
			payload = (char *)ip + ip->ip_hl * 4;
			if (ip->ip_v == IPVERSION &&
				ip->ip_p == IPPROTO_TCP &&
				((struct tcphdr *)payload)->th_flags & TH_SYN &&
				len >= (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + TCPOLEN_MAXSEG))
			{
				D_LOG("v4 tcp syn(%x)\n", ((struct tcphdr *)payload)->th_flags);
				if(rewrite_tcpmss(payload, &new_mss4))
				{
					D_LOG("mss updated!\n");

					return 1;
				}
			}
			break;
		case htons(ETHERTYPE_IPV6):
			ip6 = (struct ip6_hdr *)(ether + 1);
			payload = (char *)ip6 + sizeof(struct ip6_hdr);
			// extension header is not supported
			if ((ip6->ip6_ctlun.ip6_un2_vfc & IPV6_VERSION_MASK) == IPV6_VERSION &&
				ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP &&
				((struct tcphdr *)payload)->th_flags & TH_SYN &&
				len >= (sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + TCPOLEN_MAXSEG))
			{
				D_LOG("v6 tcp syn\n");
				if(rewrite_tcpmss(payload, &new_mss6))
				{
					D_LOG("mss updated!\n");

					return 1;
				}
			}
			break;
	}

	return 0;
}

static u_int
move_burst(uint32_t rx_ring_idx, uint32_t tx_ring_idx, u_int budget, int rewrite)
{
	struct netmap_ring *rx = NETMAP_RXRING(nm_desc->nifp, rx_ring_idx);
	struct netmap_ring *tx = NETMAP_TXRING(nm_desc->nifp, tx_ring_idx);

	u_int rx_avail = nm_ring_space(rx);
	u_int tx_space = nm_ring_space(tx);
	u_int n = rx_avail;
	if (n > tx_space) n = tx_space;
	if (n > budget)   n = budget;
	if (n == 0) return 0;

	u_int rx_cur = rx->cur;
	u_int tx_cur = tx->cur;

	for (u_int k = 0; k < n; k++) {
		struct netmap_slot *rs = &rx->slot[rx_cur];
		struct netmap_slot *ts = &tx->slot[tx_cur];

		if (rewrite) {
			void *buf = NETMAP_BUF(rx, rs->buf_idx);
			D_LOG("\n# new packet!\n");
#if DEBUG
			pctr++;
			hexdump(buf, rs->len, "  ", 0);
#endif

			check_packet(0, buf, rs->len);

#if DEBUG
			hexdump(buf, rs->len, "  ", 0);
#endif

		}

		uint32_t t = ts->buf_idx;
		ts->buf_idx = rs->buf_idx;
		rs->buf_idx = t;

		ts->len = rs->len;

		if(nm_ring_space(tx) < 64)
			ts->flags |= NS_REPORT;

		ts->flags |= NS_BUF_CHANGED;

		rx_cur = nm_ring_next(rx, rx_cur);
		tx_cur = nm_ring_next(tx, tx_cur);
	}

	rx->head = rx->cur = rx_cur;
	tx->head = tx->cur = tx_cur;

	return n;
}

static inline u_int
drop_from_rx(uint32_t rx_ring_idx, u_int max_drop)
{
	struct netmap_ring *rx = NETMAP_RXRING(nm_desc->nifp, rx_ring_idx);
	u_int avail = nm_ring_space(rx);
	u_int n = avail;
	if (n > max_drop) n = max_drop;
	if (n == 0) return 0;

	u_int cur = rx->cur;
	for (u_int k = 0; k < n; k++)
		cur = nm_ring_next(rx, cur);
	rx->head = rx->cur = cur;
	dctr += n;
	return n;
}

void
int_handler(int sig)
{
	if(nm_desc != NULL)
		nm_close(nm_desc);

#ifdef DEBUG
	printf("%lu packets received. %lu packets rewritten. ", pctr, rctr);
#endif
	printf("drops: %lu\n", dctr);
	printf("exit.\n");
	exit(0);
}

volatile sig_atomic_t dump = 0;
void
usr1_handler(int sig)
{
	dump = 1;
}

uint16_t
check_arg_mss(char* arg)
{
	char *endptr;
	long val = strtol(arg, &endptr, 10);
	if (*endptr != '\0' || val < TCP_MINMSS || val > UINT16_MAX) {
		fprintf(stderr, "Invalid MSS value: %s\n", arg);
		exit(EXIT_FAILURE);
	}

	return (uint16_t)val;
}

int
main(int argc, char *argv[])
{
	char buf[128];

	if (argc != 4)
	{
		fprintf(stderr, "usage: netmap_tcpmss <ifname> <ipv4_mss> <ipv6_mss>\n");

		exit(EXIT_FAILURE);
	}

	int lock_fd = open("/var/run/netmap_tcpmss.lock", O_CREAT|O_RDWR, 0644);
	if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) < 0) {
		    fprintf(stderr, "already running\n"); exit(1);
	}

	snprintf(buf, sizeof(buf), "netmap:%s*", argv[1]);

	new_mss4 = htons(check_arg_mss(argv[2]));
	new_mss6 = htons(check_arg_mss(argv[3]));

	signal(SIGINT, int_handler);
	signal(SIGTERM, int_handler);
	signal(SIGUSR1, usr1_handler);

	nm_desc = nm_open(buf, NULL, 0, NULL);
	if(nm_desc == NULL)
	{
		fprintf(stderr, "Failed to open netmap descriptor. exit.\n");

		exit(EXIT_FAILURE);
	}

	printf("Interface: %s, inet tcp mss: %d, inet6 tcp mss: %d\n", argv[1], ntohs(new_mss4), ntohs(new_mss6));

	clock_gettime(CLOCK_MONOTONIC, &last_progress_ts);
	int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);

	struct pollfd pollfd[1];
	uint32_t is_hostring, i, enqueued, rx_avail_total, nic_tx_first, nic_tx_last, nic_tx_num, tx_idx, moved;
	static uint32_t rr;
	for (;;)
	{
		if(dump)
		{
			dump = 0;
			fprintf(stderr, "drops=%ju, wd=%ju\n", dctr, progress_watchdog);
		}
		pollfd[0].fd = nm_desc->fd;
		pollfd[0].events = POLLIN | POLLOUT;
		if(poll(pollfd, 1, 20) < 0)
		{
			fprintf(stderr, "poll returns error");

			if(nm_desc != NULL)
				nm_close(nm_desc);

			exit(EXIT_FAILURE);
		}

		enqueued = 0;
		rx_avail_total = sum_rx_avail();
		rr = 0;
		nic_tx_first = nm_desc->first_tx_ring;
		nic_tx_last  = nm_desc->last_tx_ring;
		nic_tx_num   = (nic_tx_last > nic_tx_first) ? (nic_tx_last - nic_tx_first) : 1;
		for (i = nm_desc->first_rx_ring; i <= nm_desc->last_rx_ring; i++) {
			is_hostring = (i == nm_desc->last_rx_ring);

			tx_idx = is_hostring
				? (nic_tx_first + (rr++ % nic_tx_num))
				: nm_desc->last_tx_ring;

			moved = move_burst(i, tx_idx, 512, !is_hostring);
			if (ncpu > 0) {
				cpuset_t set; CPU_ZERO(&set);
				CPU_SET((i % ncpu), &set);
				(void)cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
						sizeof(set), &set);
			}
			
			if (moved == 0) {
				(void)ioctl(nm_desc->fd, NIOCTXSYNC, NULL);
				moved = move_burst(i, tx_idx, 512, !is_hostring);
				if (moved == 0){
					(void)drop_from_rx(i, DROP_BUDGET);
				}
			}
			enqueued |= (moved > 0);
		}

		if (enqueued) {
			if (ioctl(nm_desc->fd, NIOCTXSYNC, NULL) < 0) {
				perror("NIOCTXSYNC");
				exit(EXIT_FAILURE);
			}
			idle_loops = 0;
			clock_gettime(CLOCK_MONOTONIC, &last_progress_ts);
		} else {
			idle_loops++;
			if(rx_avail_total == 0) {
				if(idle_loops & 0x7) {
					struct timespec ts = {0, 200000};
					(void)nanosleep(&ts, NULL);
				}
				clock_gettime(CLOCK_MONOTONIC, &last_progress_ts);
			} else {
				if(elapsed_ms_since(&last_progress_ts) > 500) {
					progress_watchdog++;
					clock_gettime(CLOCK_MONOTONIC, &last_progress_ts);
				}
				struct timespec ts = {0, 100000};
				(void)nanosleep(&ts, NULL);
			}
		}
	}
}
