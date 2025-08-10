LDLIBS=-lpcap

all: arp-spoof


main.o: packetCheck.h attackPacket.h mac.h ip.h ethhdr.h arphdr.h main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

packetCheck.o : packetCheck.h packetCheck.cpp

attackPacket.o : attackPacket.h attackPacket.cpp

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o packetCheck.o attackPacket.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoofp *.o
