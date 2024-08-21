#include <sys/param.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <libutil.h>
#include <sys/sbuf.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#pragma clang diagnostic ignored "-Wunused-value"

struct nm_desc *nm_desc;
uint16_t new_mss4;
uint16_t new_mss6;
uint64_t pctr = 0;
uint64_t rctr = 0;

#define DEBUG (0)

#if DEBUG
#define D_LOG(...)	printf("%s(%d) %s:", __FILE__, __LINE__, __func__), printf(__VA_ARGS__)
#else
#define D_LOG	;
#endif


static int
rewrite_tcpmss(char *tcp, uint16_t *new_mss)
{
	struct tcphdr* tcphdr;
	tcphdr = (struct tcphdr *)tcp;
	uint16_t chksum = ntohs((uint16_t)tcphdr->th_sum);
	uint16_t hdrlen = (uint16_t)tcphdr->th_off * 4;
	uint16_t h_new_mss = ntohs(*new_mss);
	D_LOG("chksum: %x\n", chksum);
	D_LOG("tcp hdr len: %d\n", hdrlen);

	char *tcpopt;
	tcpopt = tcp + 20;
	while(*tcpopt != 0 && tcpopt - tcp < hdrlen ){
		if(*tcpopt == TCPOPT_MAXSEG)
		{
			if(*(tcpopt+1) != 4)
				return 0;

			uint16_t old_mss;
			memcpy(&old_mss, (tcpopt + 2), 2);
			uint16_t h_old_mss = ntohs(old_mss);
			D_LOG("old mss: %d\n", h_old_mss);

			if(h_old_mss <= h_new_mss)
				return 0;

			memcpy(tcpopt + 2, new_mss, 2);
			D_LOG("new mss: %d\n", ntohs((uint16_t)*(tcpopt + 2)));

			uint32_t sum;
			sum = ~chksum - h_old_mss;
			sum = (sum & 0xFFFF) + (sum >> 16);
			sum += h_new_mss;
			sum = (sum & 0xFFFF) + (sum >> 16);
			sum = (uint16_t)~sum;
			D_LOG("newcsum: %x\n", sum);

			uint16_t thsum = htons(sum);
			memcpy(&tcphdr->th_sum, &thsum, 2);

			rctr++;
			return 1;
		}
		else if(*tcpopt == TCPOPT_NOP)
		{
			D_LOG("nop\n");
			tcpopt += TCPOLEN_NOP;
		}
		else
		{
			D_LOG("unknown option\n");
			tcpopt += *(tcpopt + 1);
		}
		D_LOG("offset: %ld\n", tcpopt - tcp);
	}
	return 0;
}

static int
check_packet(int dir, void *buf, unsigned int len)
{
	char *payload;
	struct ether_header *ether;

	ether = (struct ether_header *)buf;
	uint16_t ether_type = ntohs((uint16_t)ether->ether_type);

	if (ether_type == ETHERTYPE_IP) {
		struct ip *ip;
		ip = (struct ip *)(ether + 1);
		payload = (char *)ip + ip->ip_hl * 4;
		if (ip->ip_v == IPVERSION &&
		 ip->ip_p == IPPROTO_TCP &&
		 ((struct tcphdr *)payload)->th_flags & TH_SYN ) {
			D_LOG("v4 tcp syn\n");
			if(rewrite_tcpmss(payload, &new_mss4))
			{
				D_LOG("mss updated!\n");

				return 1;
			}
		}
	} else if (ether_type == ETHERTYPE_IPV6) {
		struct ip6_hdr *ip6;
		ip6 = (struct ip6_hdr *)(ether + 1);
		payload = (char *)ip6 + 40;
		if ((ip6->ip6_ctlun.ip6_un2_vfc & IPV6_VERSION_MASK) == IPV6_VERSION &&
		 ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP &&
		 ((struct tcphdr *)payload)->th_flags & TH_SYN ) {
			D_LOG("v6 tcp syn\n");
			if(rewrite_tcpmss(payload, &new_mss6))
			{
				D_LOG("mss updated!\n");

				return 1;
			}
		}
	}

	return 0;
}

static void
swapto(int to_hostring, struct netmap_slot *rxslot)
{
	struct netmap_ring *txring;
	int i, first, last;
	uint32_t t, cur;

	if (to_hostring) {
		first = last = nm_desc->last_tx_ring;
	} else {
		first = nm_desc->first_tx_ring;
		last = nm_desc->last_tx_ring - 1;
	}

	for (i = first; i <= last; i++) {
		txring = NETMAP_TXRING(nm_desc->nifp, i);
		if (nm_ring_empty(txring))
			continue;

		cur = txring->cur;

		/* swap buf_idx */
		t = txring->slot[cur].buf_idx;
		txring->slot[cur].buf_idx = rxslot->buf_idx;
		rxslot->buf_idx = t;

		/* set len */
		txring->slot[cur].len = rxslot->len;

		/* update flags */
		txring->slot[cur].flags |= NS_BUF_CHANGED;
		rxslot->flags |= NS_BUF_CHANGED;

		/* update ring pointer */
		cur = nm_ring_next(txring, cur);
		txring->head = txring->cur = cur;

		break;
	}
}

void
int_handler(int sig)
{
	printf("%lu packets received. %lu packets rewritten. exit.\n", pctr, rctr);
	exit(0);
}

int
main(int argc, char *argv[])
{
	unsigned int cur, n, i, is_hostring;
	struct netmap_ring *rxring;
	struct pollfd pollfd[1];

	signal(SIGINT, int_handler);

	new_mss4 = htons((uint16_t)1280);
	new_mss6 = htons((uint16_t)1240);

#define NM_IFNAME	"netmap:em2*"
	nm_desc = nm_open(NM_IFNAME, NULL, 0, NULL);

	printf("Interface: %s, inet tcp mss: %d, inet6 tcp mss: %d\n", NM_IFNAME, ntohs(new_mss4), ntohs(new_mss6));

	for (;;) {
		pollfd[0].fd = nm_desc->fd;
		pollfd[0].events = POLLIN;
		poll(pollfd, 1, 100);

		for (i = nm_desc->first_rx_ring; i <= nm_desc->last_rx_ring; i++) {
			/* last ring is host ring */
			is_hostring = (i == nm_desc->last_rx_ring);

			rxring = NETMAP_RXRING(nm_desc->nifp, i);
			cur = rxring->cur;
			for (n = nm_ring_space(rxring); n > 0; n--, cur = nm_ring_next(rxring, cur)) {
				pctr++;
				D_LOG("\n# new packet!\n");
#if DEBUG
				hexdump(NETMAP_BUF(rxring, rxring->slot[cur].buf_idx), rxring->slot[cur].len, "  ", 0);
#endif

				check_packet(is_hostring, NETMAP_BUF(rxring, rxring->slot[cur].buf_idx), rxring->slot[cur].len);

#if DEBUG
				hexdump(NETMAP_BUF(rxring, rxring->slot[cur].buf_idx), rxring->slot[cur].len, "  ", 0);
#endif

				swapto(!is_hostring, &rxring->slot[cur]);
			}
			rxring->head = rxring->cur = cur;
		}
	}
}
