#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <ctype.h> 
#include <string.h>
#include <stdint.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

int hostDeny = 0;
char *hostData = NULL;

struct ipv4Header
{
    uint8_t  	ipIhlVer;
    uint8_t  	ipTos;
    uint16_t  	ipTotLen;
    uint16_t  	ipId;
    uint16_t  	ipFragOffset;
    uint8_t  	ipTTL;
    uint8_t  	ipProtocol;
    uint16_t  	ipChecksum;
    uint8_t  	ipSrcAdd[4];
    uint8_t  	ipDstAdd[4];
};

struct tcpHeader 
{
    uint16_t     tcpSrcPort;
    uint16_t     tcpDstPort;
    uint32_t     tcpSeq;
    uint32_t     tcpAckNum;
    uint8_t      tcpDataOffsetReserved;
    uint8_t      tcpFlags;
    uint16_t     tcpWindow;
    uint16_t     tcpChecksum;
    uint16_t     tcpUrgentPointer;
};

struct ipv4Header *ip4Hdr;
struct tcpHeader *tcpHdr;

#define IP_SIZE(pt)         (((pt)->ipIhlVer & 0x0F) * 4)
#define TCP_SIZE(pt)        ((((pt)->tcpDataOffsetReserved & 0xf0) >> 4) *4)

static int extractHost(const unsigned char *packet, int packetLen) {
    if (!packet || packetLen < (int)sizeof(struct ipv4Header)) return 0;

    ip4Hdr = (struct ipv4Header*)(packet);
    int ip4Siz = IP_SIZE(ip4Hdr);
    if (packetLen < ip4Siz + (int)sizeof(struct tcpHeader)) return 0;

    if (ip4Hdr->ipProtocol != 6) return 0;

    tcpHdr = (struct tcpHeader*)(packet + ip4Siz);
    int tcpSiz = TCP_SIZE(tcpHdr);

    int headerSize  = ip4Siz + tcpSiz;
    if (packetLen < headerSize) return 0;

    const uint8_t *payload = (const uint8_t *)(packet + headerSize);
    int payloadSize = packetLen - headerSize;
    if (payloadSize <= 0) return 0;

    char host[256] = {0};
    int found = 0;

    for (int i = 0; i + 4 < payloadSize; i++) {
        if (tolower((unsigned char)payload[i]) == 'h' && tolower((unsigned char)payload[i+1]) == 'o' &&tolower((unsigned char)payload[i+2]) == 's' && tolower((unsigned char)payload[i+3]) == 't' &&
            payload[i+4] == ':')
        {
            int j = i + 5;
            while (j < payloadSize && (payload[j] == ' ' || payload[j] == '\t')) j++;

            int k = 0;
            while (j < payloadSize && payload[j] != '\r' && payload[j] != '\n' && k < (int)sizeof(host) - 1) {
                if (payload[j] == ':') break;
                host[k++] = (char)payload[j++];
            }
            host[k] = '\0';

            while (k > 0 && (host[k-1] == ' ' || host[k-1] == '\t')) {
                host[--k] = '\0';
            }
            found = 1;
            break;
        }
    }

    if (!found || hostData == NULL) return 0;

    char lhs[256], rhs[256];
    for (int i = 0; host[i] && i < 255; ++i) lhs[i] = (char)tolower((unsigned char)host[i]), lhs[i+1] = 0;
    int hdlen = (int)strlen(hostData);
    if (hdlen > 255) hdlen = 255;
    memcpy(rhs, hostData, hdlen); rhs[hdlen] = '\0';
    for (int i = 0; rhs[i]; ++i) rhs[i] = (char)tolower((unsigned char)rhs[i]);

    return (strcmp(lhs, rhs) == 0) ? 1 : 0;
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d\n", ret);
		//dump(data, ret);
		hostDeny = extractHost(data, ret);
	} else {
		hostDeny = 0;
	}

	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if (hostDeny == 0) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	else if (hostDeny == 1) {
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
}

int main(int argc, char *argv[])
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	// struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	hostData = argv[1];

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

