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


struct _args {
	char hostname[1000];
	char port[100];
	int n;
} args;

/** Don't use any more threads than this or it falls apart... */
#define MAX_THREADS 60

static HANDLE threads[MAX_THREADS];


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
	int port2 = 5000;
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
			thd_args[n].n = n;

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


		/* Close all of the threads */
		for (int i = 0; i < n_thds; i++) {
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
	int n;
	char* hostname = NULL;
	char* port = NULL;
	struct addrinfo *dest = NULL;
	struct addrinfo hint;
	SOCKET sock = INVALID_SOCKET;

	/* Initialise hint */
	ZeroMemory(&hint, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;

	hostname = ((struct _args *)lpParam)->hostname;
	port = ((struct _args *)lpParam)->port;
	n = ((struct _args *)lpParam)->n;

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
	recv = connect(sock, dest->ai_addr, (int)dest->ai_addrlen);
	if (recv == SOCKET_ERROR) {
		handle = GetStdHandle(STD_OUTPUT_HANDLE);
		if (handle != INVALID_HANDLE_VALUE) {
			//printf("%s filtered\n", port);
		}
		goto thread_end;
	}

	handle = GetStdHandle(STD_OUTPUT_HANDLE);
	if (handle != INVALID_HANDLE_VALUE) {
		printf("%s open\n", port);
	}
thread_end:
	//SetEvent(threads[n]);
	closesocket(sock);
	return ret;
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