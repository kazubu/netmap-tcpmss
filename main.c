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

#if DEBUG
#define D_LOG(...)	printf("%s(%d) %s:", __FILE__, __LINE__, __func__), printf(__VA_ARGS__)
#else
#define D_LOG	;
#endif

struct nm_desc *nm_desc = NULL;
uint16_t new_mss4;
uint16_t new_mss6;
#if DEBUG
uint64_t pctr = 0;
uint64_t rctr = 0;
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

static void
swapto(int to_hostring, struct netmap_slot *rxslot)
{
	struct netmap_ring *txring;
	int i, first, last;
	uint32_t t, cur;

	if (to_hostring) {
		first = last = nm_desc->last_tx_ring;
	}
	else
	{
		first = nm_desc->first_tx_ring;
		last = nm_desc->last_tx_ring - 1;
	}

	for (i = first; i <= last; i++)
	{
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
	if(nm_desc != NULL)
		nm_close(nm_desc);

#ifdef DEBUG
	printf("%lu packets received. %lu packets rewritten. ", pctr, rctr);
#endif
	printf("exit.\n");
	exit(0);
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
	unsigned int cur, n, i, is_hostring;
	struct netmap_ring *rxring;
	struct pollfd pollfd[1];

	char buf[128];

	if (argc != 4)
	{
		fprintf(stderr, "usage: netmap_tcpmss <ifname> <ipv4_mss> <ipv6_mss>\n");

		exit(EXIT_FAILURE);
	}

	snprintf(buf, sizeof(buf), "netmap:%s*", argv[1]);

	new_mss4 = htons(check_arg_mss(argv[2]));
	new_mss6 = htons(check_arg_mss(argv[3]));

	signal(SIGINT, int_handler);
	signal(SIGTERM, int_handler);

	nm_desc = nm_open(buf, NULL, 0, NULL);
	if(nm_desc == NULL)
	{
		fprintf(stderr, "Failed to open netmap descriptor. exit.\n");

		exit(EXIT_FAILURE);
	}

	printf("Interface: %s, inet tcp mss: %d, inet6 tcp mss: %d\n", argv[1], ntohs(new_mss4), ntohs(new_mss6));

	for (;;)
	{
		pollfd[0].fd = nm_desc->fd;
		pollfd[0].events = POLLIN;
		if(poll(pollfd, 1, 100) < 0)
		{
			fprintf(stderr, "poll returns error");

			if(nm_desc != NULL)
				nm_close(nm_desc);

			exit(EXIT_FAILURE);
		}

		for (i = nm_desc->first_rx_ring; i <= nm_desc->last_rx_ring; i++)
		{
			/* last ring is host ring */
			is_hostring = (i == nm_desc->last_rx_ring);

			rxring = NETMAP_RXRING(nm_desc->nifp, i);
			cur = rxring->cur;
			for (n = nm_ring_space(rxring); n > 0; n--, cur = nm_ring_next(rxring, cur))
			{
				D_LOG("\n# new packet!\n");
#if DEBUG
				pctr++;
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
