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
void scanport(char *hostname, char *port);
DWORD WINAPI scanportthread(LPVOID lpParam);


struct scp_prm {
	char hostname[1000];
	char port[100];
	DWORD n;
} _scp_parm;

#define MAX_THREADS 100

static HANDLE threads[MAX_THREADS];


int main(int argc, char **argv)
{
	int ret = 0;
	int recv;
	WSADATA wsa;
	struct addrinfo *dest = NULL;
	struct addrinfo hint;
	SOCKET sock = INVALID_SOCKET;
	char address[] = "www.google.com";
	int port1 = 1;
	int port2 = 200;
	DWORD threadids[MAX_THREADS];
	struct scp_prm params[MAX_THREADS];
	int numthreads = 0;
	int cycles = 0;
	int end = 0;

	/* Initialise WinSock2 */
	recv = WSAStartup(MAKEWORD(2, 2), &wsa);
	if (recv != 0) {
		print_wsastartup_error(recv);
		goto main_end;
	}
	
	/* Create socket to addr:port, try to connect */
	//printf("Scanning %s between ports %d and %d\n", address, port1, port2);
	
	do {
		int range1 = port1 + (MAX_THREADS * cycles++);
		int range2 = range1 + MAX_THREADS - 1;
		if (range2 >= port2) {
			range2 = port2;
			end = 1;
		}
		printf("cycle %d: %d to %d\n", cycles, range1, range2);

		for (int i = range1, j = 0; i <= range2; i++, j++) {
			char port[10];
			_itoa_s(i, &port, 10, 10);
			strcpy_s(params[j].hostname, sizeof(params[j].hostname), address);
			strcpy_s(params[j].port, sizeof(params[j].port), port);
			params[j].n = j;

			/* Create a new thread */
			threads[j] = CreateThread(NULL, 0, scanportthread,
										&params[j], 0,
										&threadids[j]);
			if (threads[j] == NULL) {
				printf("threads[%d] == NULL\n", j);
				ExitProcess(3);
			}
			numthreads = j + 1;
			//printf("Created thread no. %d\n", j);
			//scanport(address, port);
		}
		printf("numthreads = %d\n", numthreads);
		recv = WaitForMultipleObjects((DWORD)numthreads, 
										(HANDLE)threads    , 
										(BOOL)TRUE, 
										(DWORD)5000);
		switch (recv) {
		case WAIT_ABANDONED_0:
			printf("WAIT_ABANDONED\n");
			break;
		case WAIT_TIMEOUT:
			printf("WAIT_TIMEOUT\n");
			break;
		case WAIT_FAILED:
			printf("WAIT_FAILED: %d\n", GetLastError());
			break;
		default:
			printf("ARSE\n");
			break;
		}

		printf("Closing threads\n");
		for (int i = 0; i < numthreads; i++) {
			CloseHandle(threads[i]);
		}
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
	char* hostname = NULL;
	char* port = NULL;
	TCHAR msg[100]; // w is TCHAR?
	size_t msg_buf_siz = 100;
	size_t msgsiz;
	DWORD chars; // wtf is this for?
	struct addrinfo *dest = NULL;
	struct addrinfo hint;
	SOCKET sock = INVALID_SOCKET;

	ZeroMemory(&hint, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;

	hostname = ((struct scp_prm *)lpParam)->hostname;
	port = ((struct scp_prm *)lpParam)->port;

	recv = getaddrinfo(hostname, port, &hint, &dest);
	if (recv == SOCKET_ERROR) {
		print_getaddrinfo_error(recv);
		goto thread_error;
	}

	sock = socket(dest->ai_family, dest->ai_socktype, dest->ai_protocol);
	if (sock == INVALID_SOCKET) {
		printf("%s INVALID SOCKET\n", port);
		goto thread_error;
	}
	recv = connect(sock, dest->ai_addr, (int)dest->ai_addrlen);
	if (recv == SOCKET_ERROR) {
		printf("%s filtered\n", port);
		goto thread_error;
	}

	handle = GetStdHandle(STD_OUTPUT_HANDLE);
	if (handle != INVALID_HANDLE_VALUE) {
		printf("%s open", port);
	}
thread_error:
	SetEvent(threads[((struct scp_prm *)lpParam)->n]);
	closesocket(sock);
	return ret;
}

void scanport(char *hostname, char *port)
{
	int recv;
	struct addrinfo *dest = NULL;
	struct addrinfo hint;
	SOCKET sock = INVALID_SOCKET;
	char ip[100];
	DWORD sizeofip = (DWORD)sizeof(ip);
	LPWSAPROTOCOL_INFO *lpProtocolInfo = NULL;
	struct addrinfo *tmp;

	ZeroMemory(&hint, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;

	recv = getaddrinfo(hostname, port, &hint, &dest);
	if (recv == SOCKET_ERROR) {
		print_getaddrinfo_error(recv);
		goto loop_end;
	}
	tmp = dest;
	do {
		sock = socket(dest->ai_family, dest->ai_socktype, dest->ai_protocol);
		if (sock == INVALID_SOCKET) {
			printf("INVALID_SOCKET\n");
			goto loop_end;
		}
		/* This fucking bastard function uses unicode by default, which
		is twice as wide as a char, therefore to print the fucking string
		properly, use %ls rather than %s cunt motherfucker bitch */
		recv = WSAAddressToString((LPSOCKADDR)dest->ai_addr,
			(DWORD)dest->ai_addrlen,
			NULL,
			ip,
			&sizeofip);
		if (recv != 0) {
			print_wsaaddresstostring_error(recv);
		}
		printf("%ls\n", ip);

		recv = connect(sock, dest->ai_addr, (int)dest->ai_addrlen);
		if (recv == SOCKET_ERROR) {
			printf("Filtered");
			goto loop_end;
		}
		printf("Success\n");
loop_end:
		closesocket(sock);
		tmp = dest->ai_next;
		printf("dest->ai_next = %d", tmp);
	} while (tmp != NULL);
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