#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma once
struct AttackerMacIp {
	char mac[18];
	char ip[16];
};

struct STMacIp {
	Mac mac;
	Ip ip;
};

int attackPacket(pcap_t* pcap, STMacIp SDIp, AttackerMacIp AttMacIp, char* senderIp, char* targetIp);