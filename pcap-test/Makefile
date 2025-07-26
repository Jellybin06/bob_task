TARGET=pcap-test
CXXFLAGS=-g

all: $(TARGET)

$(TARGET): pcap-test.o
		$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpcap

clean:
		rm -f $(TARGET)
		rm -f *.o
