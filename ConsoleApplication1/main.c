#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#pragma comment(lib, "Ws2_32.lib")

#include <stdio.h>
#include <WinSock2.h>
#include <ws2tcpip.h>

/*
* winsock2.h internally includes elements of windows.h
* .'. no need to include it
*
* If you do want to include windows.h, then it must be
* preceeded with the 'define WIN32_LEAN_AND_MEAN' macro
* to avoid conflict w winsock2.h
*/
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <strsafe.h>
#include <tchar.h>

void print_wsastartup_error(int error);
void print_getaddrinfo_error(int error);
void print_wsaaddresstostring_error(int error);
void printf_stringcchprintf_error(int error);
void print_sendto_error(void);
void print_getsockname_error(void);
void print_bind_error(void);
void print_connect_error(void);
void scanport(char *hostname, char *port);
const char *getportscanresult(int result);
DWORD WINAPI scanportthread(LPVOID lpParam);

struct _ipv4_hdr {
	unsigned int version : 4;
	unsigned int ihl : 4;
	unsigned int dscp : 6;
	unsigned int ecn : 2;
	unsigned int total_length : 16;
	unsigned int identification : 16;
	unsigned int flags : 3;
	unsigned int fragment_offset : 13;
	unsigned int time_to_live : 8;
	unsigned int protocol : 8;
	unsigned int header_checksum : 16;
	unsigned int source_ip_address : 32;
	unsigned int destination_ip_address : 32;
} _ipv4_header;

struct _tcp_hdr {
	unsigned int source_port : 16;
	unsigned int destination_port : 16;
	unsigned int sequence_number : 32;
	unsigned int acknowledgement_number : 32;
	unsigned int data_offset : 4;
	unsigned int reserved : 3;
	unsigned int ns : 1;
	unsigned int cwr : 1;
	unsigned int ece : 1;
	unsigned int urg : 1;
	unsigned int ack : 1;
	unsigned int psh : 1;
	unsigned int rst : 1;
	unsigned int syn : 1;
	unsigned int fin : 1;
	unsigned int window_size : 16;
	unsigned int checksum : 16;
	unsigned int urgent_pointer : 16;
} _tcp_header;

enum ipv4_ecn {
	Not_ECT = 0x0,
	ECT_1 = 0x1,
	ECT_0 = 0x2,
	CE = 0x3,
};

enum ipv4_flags {
	NO_FLAGS = 0x0,
	DONT_FRAGMENT = 0x2,
	MORE_FRAGMENTS = 0x4,
};

enum ipv4_protocol_numbers {
	HOPOPT = 0x00,
	ICMP = 0x01,
	IGMP = 0x02,
	GGP = 0x03,
	IP_IN_IP = 0x04,
	ST = 0x05,
	TCP = 0x06,
	CBT = 0x07,
	EGP = 0x08,
	IGP = 0x09,
	BBN_RCC_MON = 0x0A,
	NVP_II = 0x0B,
	PUP = 0x0C,
	ARGUS = 0x0D,
	EMCON = 0x0E,
	XNET = 0x0F,
	CHAOS = 0x10,
	UDP = 0x11
};

enum portscan_results {
	PS_TIMEOUT,
	PS_SUCCESS,
	PS_FAIL,
	PS_UNDETERMINED
};


struct _args {
	char hostname[1000];
	char port[100];
	int *result;
} args;

/** Don't use any more threads than this or it falls apart... */
#define MAX_THREADS 60
#define MAX_PACKET_SIZE 65536

static HANDLE threads[MAX_THREADS];
static HANDLE mutex;


int main(int argc, char **argv)
{
	/** Function return value */
	int ret = 0;
	/** Value returned from other functions; for error checking */
	int recv;
	/** */
	WSADATA wsa;
	/** Hostname to scan */
	char hostname[] = "www.google.com";
	/** First port in range to scan */
	int port1 = 1;
	/** Last port in range to scan */
	int port2 = 500;
	/** Array containing thread IDs */
	DWORD thd_ids[MAX_THREADS];
	/** Array of structs containing thread function arguments */
	struct _args thd_args[MAX_THREADS];
	/** Tracks number of threads active */
	int n_thds = 0;
	/** Number of do-while loops program has been through */
	int cycles = 0;
	/** Tracks whether should exit do-while loop */
	int end = 0;
	HANDLE handle;

	/* Initialise WinSock2 */
	recv = WSAStartup(MAKEWORD(2, 2), &wsa);
	if (recv != 0) {
		print_wsastartup_error(recv);
		goto main_end;
	}

	/** Scan MAX_THREADS ports at a time, keep going through this
	* loop until we've covered the whole range
	*/
	do {
		/** The first port in the current range to scan */
		int range1 = port1 + (MAX_THREADS * cycles++);
		/** Second port in current range to scan */
		int range2 = range1 + MAX_THREADS - 1;
		/* If range2 larger than largest port num to scan, then set it
		* to largest port num
		*/
		if (range2 >= port2) {
			range2 = port2;
			end = 1;
		}
		handle = GetStdHandle(STD_OUTPUT_HANDLE);
		if (handle != INVALID_HANDLE_VALUE) {
			printf("cycle %d: %d to %d\n", cycles, range1, range2);
		}

		// Create a mutex
		mutex = CreateMutex(NULL, FALSE, NULL);
		if (mutex == NULL) {
			printf("CreateMutex error: %d\n", GetLastError());
			goto main_end;
		}

		int results[MAX_THREADS];


		/** Initialise thd_args, create thread, and keep track of
		*	no of threads created
		* i: Current port number
		* n: Position in thread array
		*/
		for (int i = range1, n = 0; i <= range2; i++, n++) {
			/** Current port number as a string */
			char port[10];
			/** Convert i to string */
			_itoa_s(i, &port, 10, 10);
			strcpy_s(thd_args[n].hostname, sizeof(thd_args[n].hostname), hostname);
			strcpy_s(thd_args[n].port, sizeof(thd_args[n].port), port);
			thd_args[n].result = &results[n];

			/* Create a new thread */
			threads[n] = CreateThread(NULL, 0, scanportthread,
				&thd_args[n], 0,
				&thd_ids[n]);
			if (threads[n] == NULL) {
				printf("threads[%d] == NULL\n", n);
				ExitProcess(3);
			}
			/* Number of threads is one larger than position in array */
			n_thds = n + 1;
		}

		/* Wait for all of the current threads to finish */
		recv = WaitForMultipleObjects((DWORD)n_thds,
			(HANDLE)threads,
			(BOOL)TRUE,
			(DWORD)INFINITE);
		/* Print results */
		for (int i = 0; i < n_thds; i++) {
			printf("%s:%s = %s\n", thd_args[i].hostname, thd_args[i].port,
				getportscanresult(thd_args[i].result));
		}

		/* Close all of the threads */
		for (int i = 0; i < n_thds; i++) {
			CloseHandle(threads[i]);
		}
		// for each 
	} while (end == 0);

	printf("All ports scanned.\n");
main_end:
	printf("Press enter to exit.\n");
	getchar();
	return ret;
}

DWORD WINAPI scanportthread(LPVOID lpParam)
{
	HANDLE handle;
	int ret = 0;
	int recv;
	int n;
	char* hostname = NULL;
	char* port = NULL;
	struct addrinfo *dest = NULL;
	struct addrinfo hint;
	struct sockaddr sockaddr;
	socklen_t sockaddr_len = sizeof(sockaddr);
	SOCKET sock = INVALID_SOCKET;
	int *result;

	char packet[MAX_PACKET_SIZE];
	struct _ipv4_hdr *ipv4hdr = (struct _ipv4_hdr *)packet;
	struct _tcp_hdr *tcphdr = (struct _tcp_hdr *)(packet + sizeof(*ipv4hdr));
	char *data = packet + sizeof(*ipv4hdr) + sizeof(*tcphdr);
	int datalen = 100;

	char buf[100];
	struct in_addr *tmp;

	/* Initialise hint */
	ZeroMemory(&hint, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_RAW;
	hint.ai_protocol = IPPROTO_RAW;

	hostname = ((struct _args *)lpParam)->hostname;
	port = ((struct _args *)lpParam)->port;
	result = &((struct _args *)lpParam)->result;
	*result = PS_UNDETERMINED;

	//printf("%s%s\n", hostname, port);

	recv = getaddrinfo(hostname, port, &hint, &dest);
	if (recv == SOCKET_ERROR) {
		print_getaddrinfo_error(recv);
		goto thread_end;
	}

	sock = socket(dest->ai_family, dest->ai_socktype, dest->ai_protocol);
	if (sock == INVALID_SOCKET) {
		handle = GetStdHandle(STD_OUTPUT_HANDLE);
		if (handle != INVALID_HANDLE_VALUE) {
			printf("%s INVALID SOCKET\n", port);
		}
		goto thread_end;
	}

	recv = connect(sock, dest->ai_addr, (int)dest->ai_addrlen);;
	if (recv == SOCKET_ERROR) {
		handle = GetStdHandle(STD_OUTPUT_HANDLE);
		if (handle != INVALID_HANDLE_VALUE) {
			print_connect_error();
		}
		goto thread_end;
	}
	recv = getsockname(sock, &sockaddr, &(int)sockaddr_len);
	if (recv == -1) {
		handle = GetStdHandle(STD_OUTPUT_HANDLE);
		if (handle != INVALID_HANDLE_VALUE) {
			print_getsockname_error();
		}
		goto thread_end;
	}

	/* Initialise IPv4 header */
	ipv4hdr->version = 4;
	ipv4hdr->ihl = 5; /* Should calc. this... */
	ipv4hdr->dscp = 0;
	ipv4hdr->ecn = Not_ECT; /* Not-ECT */
	ipv4hdr->total_length = htons(sizeof(*ipv4hdr) + sizeof(*tcphdr) + datalen); /* To be assigned later */
	ipv4hdr->identification = 0; /* To be assigned later */
	ipv4hdr->flags = NO_FLAGS;
	ipv4hdr->fragment_offset = 0;
	ipv4hdr->time_to_live = 128;
	ipv4hdr->protocol = IPPROTO_TCP;
	ipv4hdr->header_checksum = 0; /* To be assigned later */
	/* Turn IP strs to ints then copy */
	tmp = &((struct sockaddr_in *)&sockaddr)->sin_addr;
	inet_ntop(AF_INET, &tmp, buf, sizeof(buf));
	ipv4hdr->source_ip_address = inet_addr(buf);
	tmp = &((struct sockaddr_in *)dest->ai_addr)->sin_addr;
	inet_ntop(AF_INET, &tmp, buf, sizeof(buf));
	ipv4hdr->destination_ip_address = inet_addr(buf);

	/* Initialise TCP header */
	tcphdr->source_port = ((struct sockaddr_in *)&sockaddr)->sin_port;
	tcphdr->destination_port = htons(atof(port)); /* Dest str to int */
	tcphdr->cwr = 0;
	tcphdr->ece = 1;
	tcphdr->urg = 0;
	tcphdr->ack = 0;
	tcphdr->psh = 0;
	tcphdr->rst = 1;
	tcphdr->syn = 0;
	tcphdr->fin = 0;
	tcphdr->ns = 1;
	tcphdr->checksum = 0; /* Assign later */

						  /* Initialise data payload */
	memset(data, 'X', datalen);
	recv = sendto(sock, &packet,
		sizeof(*ipv4hdr) + sizeof(*tcphdr) + datalen,
		0, dest->ai_addr, sizeof(*dest->ai_addr));
	if (recv == SOCKET_ERROR) {
		handle = GetStdHandle(STD_OUTPUT_HANDLE);
		if (handle != INVALID_HANDLE_VALUE) {
			print_sendto_error();
		}
		goto thread_end;
	}
	*result = PS_SUCCESS;
thread_end:
	closesocket(sock);
	return ret;
}

const char *getportscanresult(int result)
{
	printf("%d", result);
	switch (result) {
	case PS_SUCCESS:
		return "SUCCESS";
	case PS_TIMEOUT:
		return "TIMEOUT";
	case PS_FAIL:
		return "FAIL";
	case PS_UNDETERMINED:
		return "UNDETERMINED";
	default:
		return "DEFAULT";
	}
}

void print_connect_error(void)
{
	printf("connect() error: ");
	switch (WSAGetLastError()) {
	case WSANOTINITIALISED:
		printf("WSANOTINITIALISED");
		break;
	case WSAENETDOWN:
		printf("WSAENETDOWN");
		break;
	case WSAEADDRINUSE:
		printf("WSAEADDRINUSE");
		break;
	case WSAEINTR:
		printf("WSAEINTR");
		break;
	case WSAEINPROGRESS:
		printf("WSAEINPROGRESS");
		break;
	case WSAEALREADY:
		printf("WSAEALREADY");
		break;
	case WSAEADDRNOTAVAIL:
		printf("WSAEADDRNOTAVAIL");
		break;
	case WSAEAFNOSUPPORT:
		printf("WSAEAFNOSUPPORT");
		break;
	case WSAECONNREFUSED:
		printf("WSAECONNREFUSED");
		break;
	case WSAEFAULT:
		printf("WSAEFAULT");
		break;
	case WSAEINVAL:
		printf("WSAEINVAL");
		break;
	case WSAEISCONN:
		printf("WSAEISCONN");
		break;
	case WSAENETUNREACH:
		printf("WSAENETUNREACH");
		break;
	case WSAENOBUFS:
		printf("WSAENOBUFS");
		break;
	case WSAENOTSOCK:
		printf("WSAENOTSOCK");
		break;
	case WSAETIMEDOUT:
		printf("WSAETIMEDOUT");
		break;
	case WSAEWOULDBLOCK:
		printf("WSAEWOULDBLOCK");
		break;
	case WSAEACCES:
		printf("WSAEACCES");
		break;
	default:
		printf("default");
		break;
	}
	printf("\n");
	return;
}

void print_bind_error(void)
{
	printf("bind() error: ");
	switch (WSAGetLastError()) {
	case WSANOTINITIALISED:
		printf("WSANOTINITIALISED");
		break;
	case WSAENETDOWN:
		printf("WSAENETDOWN");
		break;
	case WSAEACCES:
		printf("WSAEACCES");
		break;
	case WSAEADDRINUSE:
		printf("WSAEADDRINUSE");
		break;
	case WSAEADDRNOTAVAIL:
		printf("WSAEADDRNOTAVAIL");
		break;
	case WSAEFAULT:
		printf("WSAEFAULT");
		break;
	case WSAEINPROGRESS:
		printf("WSAEINPROGRESS");
		break;
	case WSAEINVAL:
		printf("WSAEINVAL");
		break;
	case WSAENOBUFS:
		printf("WSAENOBUFS");
		break;
	case WSAENOTSOCK:
		printf("WSAENOTSOCK");
		break;
	default:
		printf("default");
		break;
	}
	printf("\n");
	return;
}

void print_sendto_error(void)
{
	printf("sendto() error: ");
	switch (WSAGetLastError()) {
	case WSANOTINITIALISED:
		printf("WSANOTINITIALISED\n");
		break;
	case WSAENETDOWN:
		printf("WSAENETDOWN\n");
		break;
	case WSAEACCES:
		printf("WSAEACCES\n");
		break;
	case WSAEINVAL:
		printf("WSAEINVAL\n");
		break;
	case WSAEINTR:
		printf("WSAEINTR\n");
		break;
	case WSAEINPROGRESS:
		printf("WSAEINPROGRESS\n");
		break;
	case WSAEFAULT:
		printf("WSAEFAULT\n");
		break;
	case WSAENETRESET:
		printf("WSAENETRESET\n");
		break;
	case WSAENOBUFS:
		printf("WSAENOBUFS\n");
		break;
	case WSAENOTCONN:
		printf("WSAENOTCONN\n");
		break;
	case WSAENOTSOCK:
		printf("WSAENOTSOCK\n");
		break;
	case WSAEOPNOTSUPP:
		printf("WSAEOPNOTSUPP\n");
		break;
	case WSAESHUTDOWN:
		printf("WSAESHUTDOWN\n");
		break;
	case WSAEWOULDBLOCK:
		printf("WSAEWOULDBLOCK\n");
		break;
	case WSAEMSGSIZE:
		printf("WSAEMSGSIZE");
		break;
	case WSAEHOSTUNREACH:
		printf("WSAEHOSTUNREACH");
		break;
	case WSAECONNABORTED:
		printf("WSAECONNABORTED");
		break;
	case WSAECONNRESET:
		printf("WSAECONNRESET\n");
		break;
	case WSAEADDRNOTAVAIL:
		printf("WSAEADDRNOTAVAIL\n");
		break;
	case WSAEAFNOSUPPORT:
		printf("WSAEAFNOSUPPORT\n");
		break;
	case WSAEDESTADDRREQ:
		printf("WSAEFESTADDREQ\n");
		break;
	case WSAENETUNREACH:
		printf("WSAENETUNREACH\n");
		break;
		//	case WSAEHOSTUNREACH:
		//		printf("WSAEHOSTUNREACH\n");
		//		break;
	case WSAETIMEDOUT:
		printf("WSAETIMEDOUT\n");
		break;
	default:
		printf("DEFAULT\n");
		break;

	}
	return;
}

void print_waitformultipleobjects_error(int error)
{
	switch (error) {
	case WAIT_ABANDONED_0:
		printf("WAIT_ABANDONED\n");
		break;
	case WAIT_ABANDONED_0 + 1:
		printf("WAIT_ABANDONED_0 + 1");
	case WAIT_TIMEOUT:
		printf("WAIT_TIMEOUT\n");
		break;
	case WAIT_FAILED:
		printf("WAIT_FAILED: %d\n", GetLastError());
		break;
	}
}

void print_wsastartup_error(int error)
{
	switch (error) {
	case WSASYSNOTREADY:
		printf("WSASYSNOTREADY\n");
		break;
	case WSAVERNOTSUPPORTED:
		printf("WSAVERNOTSUPPORTED\n");
		break;
	case WSAEINPROGRESS:
		printf("WSAEINPROGRESS\n");
		break;
	case WSAEPROCLIM:
		printf("WSAEPROCLIM\n");
		break;
	case WSAEFAULT:
		printf("WSAEFAULT\n");
		break;
	default:
		printf("NO IDEA LOL\n");
		break;
	}
	return;
}

void print_getaddrinfo_error(int error)
{
	switch (error) {
	case WSATRY_AGAIN:
		printf("WSATRY_AGAIN\n");
		break;
	case WSAEINVAL:
		printf("WSAEINVAL\n");
		break;
	case WSANO_RECOVERY:
		printf("WSANO_RECOVERY\n");
		break;
	case WSAEAFNOSUPPORT:
		printf("WSAEAFNOSUPPORT\n");
		break;
	case WSA_NOT_ENOUGH_MEMORY:
		printf("WSA_NOT_ENOUGH_MEMORY\n");
		break;
	case WSATYPE_NOT_FOUND:
		printf("WSATYPE_NOT_FOUND\n");
		break;
	case WSAESOCKTNOSUPPORT:
		printf("WSAESOCKTNOSUPPORT\n");
		break;
	default:
		printf("SHOULDN'T BE HERE\n");
	}
	return;
}

void print_wsaaddresstostring_error(int error)
{
	switch (WSAGetLastError()) {
	case WSAEFAULT:
		printf("WSAEFAULT\n");
		break;
	case WSAEINVAL:
		printf("WSAEINVAL\n");
		break;
	case WSAENOBUFS:
		printf("WSAENOBUFS\n");
		break;
	case WSANOTINITIALISED:
		printf("WSANOTINITIALISED\n");
		break;
	default:
		printf("FUCK\n");
		break;
	}
	return;
}

void printf_stringcchprintf_error(int error)
{
	switch (error) {
	case STRSAFE_E_INVALID_PARAMETER:
		printf("STRSAFE_E_INVALID_PARAMETER\n");
		break;
	case STRSAFE_E_INSUFFICIENT_BUFFER:
		printf("STRSAFE_E_INSUFFICIENT_BUFFER\n");
		break;
	default:
		printf("CUNT\n");
		break;
	}
	return;
}

void print_getsockname_error(void)
{
	printf("getsockname(): %d\n", WSAGetLastError());
	return;
}