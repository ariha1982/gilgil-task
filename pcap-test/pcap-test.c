#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "network-headers.h"
#include <netinet/in.h>

#define IPv4_ETHERTYPE 0x0800
#define ARP_ETHERTYPE 0x0806
#define IPv6_ETHERTYPE 0x86DD
#define TCP_PROTOCOL 0x06
#define UDP_PROTOCOL 0x11

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

struct ip_result
{
	bool success;
	uint8_t ip_h_length;
};


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

int parse_eth_h(const unsigned char* packet) {
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

	// ether type이 ipv4가 아닐 경우 처리
	uint16_t ether_type = ntohs(eth_h -> ether_type);
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
		
		printf("⚠️ EtherType is not IPv4. EtherType: %s(0x%04x)\n", other_type, ether_type);
		return -1;
	}

	return 0;
}

struct ip_result parse_ipv4_h(const unsigned char* packet) {
	struct ipv4_hdr* ipv4_h = (struct ipv4_hdr *)(packet + 14);

	printf("Source IP: %s\n", inet_ntoa(ipv4_h -> ip_src));
	printf("Destination IP: %s\n", inet_ntoa(ipv4_h -> ip_dst));

	uint8_t ip_protocol = ipv4_h -> ip_p;
	int return_status;
	if (ip_protocol != TCP_PROTOCOL)
	{
		return_status = false;

		char *other_protocol;
		if (ip_protocol == UDP_PROTOCOL){
			other_protocol = "UDP";
		} else {
			other_protocol = "Wrong Protocol";
		}
		
		printf("⚠️ Protcol is not TCP. Protocol: %s(0x%x)\n", other_protocol, ip_protocol);
	}

	return_status = true;
	uint8_t ip_h_len = (ipv4_h -> ip_vhl) & 0x0F;
	struct ip_result result = {return_status, ip_h_len * 4};

	return result;
}

void parse_tcp_h(const unsigned char* packet, uint8_t offset) {
	struct tcp_hdr* tcp_h = (struct tcp_hdr *)(packet + offset);
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
		if (parse_eth_h(packet) == -1){ continue; }


		// 2. ipv4 header
		struct ip_result ip_result = parse_ipv4_h(packet);
		if (!ip_result.success){ continue; }
		
		// TCP가 아닐 경우 종료
		parse_tcp_h(packet, 14 + ip_result.ip_h_length);
		

		// 3. tcp header

		// 4. data
	}

	pcap_close(pcap);
}