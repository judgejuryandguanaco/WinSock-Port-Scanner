#include <stdio.h>
#include <WinSock2.h>
//#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "Ws2_32.lib")

#ifndef _WINSOCK_DEPRECATES_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif


struct ip_hdr {
	unsigned char ip_header_len : 4;
	unsigned char ip_version : 4;
	unsigned char ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;

	unsigned char ip_frag_offset : 5;

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1;

	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	unsigned int ip_srcaddr;
	unsigned int ip_destaddr;
} ipv4_hdr; // *PIPV4_HDR, FAR * LIPIPV4_HDR 

struct tcp_header {
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;

	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;

	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;

	unsigned char ecn : 1;
	unsigned char cwr : 1;

	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
} tcp_hdr; // TCP_HDR, *PTCP_HDR, FAR * LPTCP_HDR, TCPHeader, TCP_HEADER

int main()
{
	/* Socket */
	SOCKET sock = INVALID_SOCKET;
	struct addrinfo *dest = NULL;
	struct addrinfo hints;
	char url[100] = "www.google.com";
	char port[10];
	/* Raw packet */
	char packet[65536]; // why this size?
	char payload = 100;

	/* Start up WinSock */

	for (int i = 75; i <= 85; i++) {
		_itoa(i, port, 10, 10);
		/* Clear hints for use in getaddrinfo() */
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_RAW;
		hints.ai_flags = AI_PASSIVE;
		/* Turn domain string info into host address stuff mgga wgga */
		getaddrinfo(url, port, &hints, &dest);
		g
		/* Initialise socket */
		sock = socket(dest->ai_family, dest->ai_socktype, dest->ai_protocol);

		/* Set up SYN packet */
		setupsynpacket(&pkt, );

		closesocket(sock);
	}
	return 0;
}

void setupsynpacket(char *pkt, unsigned int src_addr, unsigned int dest_addr, 
					unsigned short src_port, unsigned short dest_port)
{
	struct ipv4_hdr *ipv4hdr = (struct ipv4_hdr *)packet;
	struct tcp_hdr(struct tcp_hdr *)&packet[sizeof(*ipv4hdr)];
	char *data = packet[sizeof(*ipv4_hdr) + sizeof(*tcp_hdr)];

	/* Set up IP header */
	pkt->ip_version = 4;
	pkt->ip_header_len = 5;
	pkt->ip_tos = 0;
	pkt->ip_total_length = htons(sizeof(ipv4hdr) + sizeof(tcp_hdr) +
		sizeof(payload));
	pkt->ip_id = htons(2);
	pkt->ip_frag_offset = 0;
	pkt->ip_reserved_zero = 0;
	pkt->ip_dont_fragment = 1;
	pkt->ip_more_frament = 0;
	pkt->ip_ttl = 8;
	pkt->ip_protocol = IPPROTO_TCP;
	pkt->ip_srcaddr = inet_addr(src);
	pkt->ip_destaddr = inet_addr();

	/* Set up TCP header */
	pkt->source_port = htons();
	pkt->dest_port = htons();
	pkt->cwr = 0;
	pkt->ecn = 0;
	pkt->urg = 0;
	pkt->ack = 0;
	pkt->psh = 0;
	pkt->rst = 1;
	pkt->syn = 0;
	pkt->fin = 0;
	pkt->ns = 1;
	pkt->checksum = 0;

	/* Add data to packet */
	memset(data, "^", payload);
}