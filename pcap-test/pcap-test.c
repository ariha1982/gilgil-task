#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "network-headers.h"
#include <netinet/in.h>

#define IPv4_ETHERTYPE 0x0800
#define ARP_ETHERTYPE 0x0806
#define IPv6_ETHERTYPE 0x86DD

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

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

uint16_t parse_eth_h(const unsigned char* packet) {
	// Mapping
	struct eth_hdr* eth_h = (struct eth_hdr *)packet;

	// Src MAC
	printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
		eth_h -> ether_shost[0],
		eth_h -> ether_shost[1],
		eth_h -> ether_shost[2],
		eth_h -> ether_shost[3],
		eth_h -> ether_shost[4],
		eth_h -> ether_shost[5]
	);

	// Dst MAC
	printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
		eth_h -> ether_dhost[0],
		eth_h -> ether_dhost[1],
		eth_h -> ether_dhost[2],
		eth_h -> ether_dhost[3],
		eth_h -> ether_dhost[4],
		eth_h -> ether_dhost[5]
	);

	return ntohs(eth_h -> ether_type);
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const unsigned char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		// 1. eth header
		uint16_t ether_type = parse_eth_h(packet);
		printf("0x%04x\n", ether_type);

		// 예외1. ether type이 ipv4가 아닐 경우 종료
		if (ether_type != IPv4_ETHERTYPE)
		{
			char *other_type;
			if (ether_type == ARP_ETHERTYPE){
				other_type = "ARP";
			} else if (ether_type == IPv6_ETHERTYPE) {
				other_type = "IPv6";
			} else {
				other_type = "Wrong Value";
			}
			
			printf("⚠️EtherType is not IPv4. EtherType: %s(0x%04x)\n", other_type, ether_type);
			return -1;
		}

		// 2. ipv4 header
		
		// 3. tcp header

		// 4. data
	}

	pcap_close(pcap);
}