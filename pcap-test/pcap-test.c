#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "network-headers.h"
#include <netinet/in.h>

#define IPv4_ETHERTYPE 0x0800
#define TCP_PROTOCOL 0x06
#define IPv4_MIN_SIZE 20
#define TCP_MIN_SIZE 20

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

struct parsing_result {
	int *parsed_eth;
	int *parsed_ip;
	int *parsed_tcp;
	int *payload;
};

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

void print_packet(const unsigned char* packet, struct eth_hdr* eth, struct ipv4_hdr* ip, struct tcp_hdr* tcp, uint8_t offset) {
	// Src Host
	printf("Src Host: %02x:%02x:%02x:%02x:%02x:%02x\n", 
		eth -> ether_shost[0],
		eth -> ether_shost[1],
		eth -> ether_shost[2],
		eth -> ether_shost[3],
		eth -> ether_shost[4],
		eth -> ether_shost[5]
	);

	// Dst Host
	printf("Dst Host: %02x:%02x:%02x:%02x:%02x:%02x\n", 
		eth -> ether_dhost[0],
		eth -> ether_dhost[1],
		eth -> ether_dhost[2],
		eth -> ether_dhost[3],
		eth -> ether_dhost[4],
		eth -> ether_dhost[5]
	);
	
	// Src IP
	printf("Src IP: %s\n", inet_ntoa(ip -> ip_src));

	// Dst IP
	printf("Dst IP: %s\n", inet_ntoa(ip -> ip_dst));

	// Src Port
	printf("Src Port: %d\n", tcp -> th_sport);
	
	// Dst Port
	printf("Dst Port: %d\n", tcp -> th_dport);

	// Data
	printf("Data: ");
	for(int i = offset; i < offset + 20; i++) {
		printf("%0x ", packet[i]);
	}
	
	printf("\n\n");
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

		uint32_t total_len = header -> caplen;
		uint8_t offset = 0;
		
		// 1. ethernet header
		if (total_len < sizeof(struct eth_hdr)) continue; // 전체 길이 < ethernet header -> 패스

		struct eth_hdr* ethernet = (struct eth_hdr *)packet;
		
		// ethertype이 ipv4가 아닐 경우 패스
		if (ntohs(ethernet -> ether_type) != IPv4_ETHERTYPE) continue;
		offset += sizeof(struct	eth_hdr);

		// 2. ipv4 header
		if (total_len - offset < IPv4_MIN_SIZE) continue; // 남은 길이 < IPv4 최소 길이 -> 패스

		struct ipv4_hdr* ipv4 = (struct ipv4_hdr *)(packet + offset);
		// protocol이 tcp가 아닐 경우 패스
		if ((ipv4 -> ip_p) != TCP_PROTOCOL) continue;
		offset += ((ipv4 -> ip_vhl) & 0x0F);

		// 3. tcp header
		if (total_len - offset < TCP_MIN_SIZE) continue; // 남은 길이 < TCP 최소 길이 -> 패스

		struct tcp_hdr* tcp = (struct tcp_hdr *)(packet + offset);
		offset += ((tcp -> th_x2off) & 0xF0);

		// 4. print
		print_packet(packet, ethernet, ipv4, tcp, offset);
	}

	pcap_close(pcap);
}