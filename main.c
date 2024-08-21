#include <sys/param.h>
#include <unistd.h>
#include <poll.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <libutil.h>
#include <sys/sbuf.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

struct nm_desc *nm_desc;


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
		if (ip->ip_v == IPVERSION && ip->ip_p == IPPROTO_TCP && ((struct tcphdr *)payload)->th_flags & TH_SYN ) {
			printf("v4 tcp syn\n");
		}
	} else if (ether_type == ETHERTYPE_IPV6) {
		struct ip6_hdr *ip6;
		ip6 = (struct ip6_hdr *)(ether + 1);
		payload = (char *)ip6 + 40;
		if ((ip6->ip6_ctlun.ip6_un2_vfc & IPV6_VERSION_MASK) == IPV6_VERSION && ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP && ((struct tcphdr *)payload)->th_flags & TH_SYN ) {
			printf("v6 tcp syn\n");
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

int
main(int argc, char *argv[])
{
	unsigned int cur, n, i, is_hostring;
	struct netmap_ring *rxring;
	struct pollfd pollfd[1];

#define NM_IFNAME	"netmap:em2*"
	nm_desc = nm_open(NM_IFNAME, NULL, 0, NULL);

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

				check_packet(is_hostring, NETMAP_BUF(rxring, rxring->slot[cur].buf_idx), rxring->slot[cur].len);
				hexdump(NETMAP_BUF(rxring, rxring->slot[cur].buf_idx), rxring->slot[cur].len, "  ", 0);

				swapto(!is_hostring, &rxring->slot[cur]);
			}
			rxring->head = rxring->cur = cur;
		}
	}
}
