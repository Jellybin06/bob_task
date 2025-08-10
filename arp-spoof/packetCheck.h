#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "attackPacket.h"
#include <pcap.h>
#include <stdlib.h>

void packetCheck(char* dev, STMacIp SDIp, STMacIp TGIp, AttackerMacIp AttMacIp, char* senderIp, char* targetIp);

