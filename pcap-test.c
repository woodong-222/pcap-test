#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include "pcap-test.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

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

void capture_ethernet(const u_char* packet)
{
	EthernetHeader *ethernet = (EthernetHeader*)packet;

	printf("src mac:\t");
	for(uint8_t i = 0; i< ETHERNET_MAC_SIZE; i++)
	{
		printf("%02x", ethernet->source_mac_address[i]);
		if(i < ETHERNET_MAC_SIZE - 1) printf(":");
	}
	printf("\n");


	printf("dst mac:\t");
	for(uint8_t i = 0; i< ETHERNET_MAC_SIZE; i++)
	{
		printf("%02x", ethernet->destination_mac_address[i]);
		if(i < ETHERNET_MAC_SIZE - 1) printf(":");
	}
	printf("\n");
}

void capture_ipv4(const u_char* packet)
{
	Ipv4Header *ipv4 = (Ipv4Header*) packet;
	uint32_t ip;
	ip = ntohl(ipv4->source_address);
	printf("src ip:\t\t%d.%d.%d.%d\n", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);

	ip = ntohl(ipv4->destination_address);
	printf("dst ip:\t\t%d.%d.%d.%d\n", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

void capture_tcp(const u_char* packet)
{
	TcpHeader *tcp = (TcpHeader*) packet;

	printf("src port:\t%d\n", ntohs(tcp->source_port));
	printf("dst port:\t%d\n", ntohs(tcp->destination_port));
}

void capture_payload(const u_char* packet)
{
	printf("payload(data):\t");
	for(int i = 0; i < 20; i++) {
		printf("%02x ", packet[i]);
	}
	printf("\n");
}

void capture(const u_char* packet)
{
	capture_ethernet(packet);
	capture_ipv4(packet + ETHERNET_SIZE);
	capture_tcp(packet + ETHERNET_SIZE + IPV4_SIZE);
	capture_payload(packet + ETHERNET_SIZE + IPV4_SIZE + TCP_SIZE);
	printf("---------------------------------------------------------------------------\n");
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
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		if ((*(uint8_t*)(packet+PROTOCOL) == TCP)) capture(packet);
	}

	pcap_close(pcap);
}
