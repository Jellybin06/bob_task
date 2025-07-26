#include <pcap.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#define ETHERNET_SIZE       14
#define ETHER_HEADER_LEN    6
#define IP_HEADER_LEN       4
#define PCAP_SUCCESS        1
#define PCAP_FAIL           0

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

struct ethernetHeader {
    uint8_t macDstAdd[ETHER_HEADER_LEN];
    uint8_t macSrcAdd[ETHER_HEADER_LEN];
    uint16_t macEnterType;
};

struct ipv4Header
{
    uint8_t  ipIhlVer;
    uint8_t  ipTos;
    uint16_t  ipTotLen;
    uint16_t  ipId;
    uint16_t  ipFragOffset;
    uint8_t  ipTTL;
    uint8_t  ipProtocol;
    uint16_t  ipChecksum;
    uint8_t  ipSrcAdd[IP_HEADER_LEN];
    uint8_t  ipDstAdd[IP_HEADER_LEN];
};

struct tcpHeader 
{
    uint16_t     tcpSrcPort;
    uint16_t     tcpDstPort;
    uint32_t    tcpSeq;
    uint32_t    tcpAckNum;
    uint8_t     tcpDataOffsetReserved;
    uint8_t     tcpFlags;
    uint16_t     tcpWindow;
    uint16_t     tcpChecksum;
    uint16_t     tcpUrgentPointer;
};

const struct ethernetHeader *ethernet;
const struct ipv4Header     *ip;
const struct tcpHeader      *tcp;

#define IP_SIZE(pt)         (((pt)->ipIhlVer & 0x0F) * 4)
#define TCP_SIZE(pt)        ((((pt)->tcpDataOffsetReserved & 0xf0) >> 4) *4)

void printEthernet(const uint8_t* macSrcAdd, const uint8_t* macDstAdd) {
    printf("==========ETHERNET==========\n");
    printf("Ethernet Src = %02x:%02x:%02x:%02x:%02x:%02x\n", macSrcAdd[0],macSrcAdd[1],macSrcAdd[2],macSrcAdd[3],macSrcAdd[4],macSrcAdd[5]);
    printf("Ethernet Dst = %02x:%02x:%02x:%02x:%02x:%02x\n", macDstAdd[0],macDstAdd[1],macDstAdd[2],macDstAdd[3],macDstAdd[4],macDstAdd[5]);
    printf("============================\n");
}

void printIpv4(const uint8_t* ipSrcAdd, const uint8_t* ipDstAdd) {
    printf("=============IP=============\n");
    printf("IP Src = %d.%d.%d.%d\n", ipSrcAdd[0],ipSrcAdd[1],ipSrcAdd[2],ipSrcAdd[3]);
    printf("IP Dst = %d.%d.%d.%d\n", ipDstAdd[0],ipDstAdd[1],ipDstAdd[2],ipDstAdd[3]);
    printf("============================\n");
}

void printTcp(uint16_t tcpSrcPort, uint16_t tcpDstPort) {
    printf("=============TCP============\n");
    printf("TCP SrcPort = %d\n", tcpSrcPort);
    printf("TCP DstPort = %d\n", tcpDstPort);
    printf("============================\n");
}

void printPayload(const uint8_t* payload, int payloadSize) {
    printf("===========PAYLOAD==========\n");
    if (20 < payloadSize) payloadSize = 20;
    for(int i = 0; i < payloadSize; i++) {
        printf("%02x ", payload[i]);
    }
    printf("\n");
    printf("============================\n");
}

void printPcap(struct pcap_pkthdr* header, const uint8_t* packet) {
    uint8_t *payload;
    ethernet        = (struct ethernetHeader*)(packet);
    ip              = (struct ipv4Header*)(packet+ETHERNET_SIZE);
    int ipSize      = IP_SIZE(ip);
    tcp             = (struct tcpHeader*)(packet+ETHERNET_SIZE+ipSize);
    int tcpSize     = TCP_SIZE(tcp);
    payload         = (uint8_t *)(packet + ETHERNET_SIZE + ipSize + tcpSize);
    int headerSize  = ETHERNET_SIZE + ipSize + tcpSize;
    int payloadSize = header->caplen - headerSize;
    printf("======PACKET_CAPTURED=======\n");
    printEthernet(ethernet->macSrcAdd, ethernet->macDstAdd);
    printIpv4((ip->ipSrcAdd), ip->ipDstAdd);
    printTcp(ntohs(tcp->tcpSrcPort), ntohs(tcp->tcpDstPort));
    printPayload(payload, payloadSize);
    printf("\n");
}

int getPacketData() {
    pcap_t* pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return PCAP_FAIL;
    }
    while (true) {
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if ((res == PCAP_ERROR) || (res == PCAP_ERROR_BREAK)) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printPcap(header, packet);
    }
    pcap_close(pcap);
    return PCAP_SUCCESS;
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
		return -1;

    if (!getPacketData()) return -1;
    return 0;
}