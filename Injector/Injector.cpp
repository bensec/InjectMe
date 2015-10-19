// Injector.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

__declspec(naked) void stub()
{
	__asm
	{
		pushad
		pushfd
		call start

		start:
			pop ecx
			sub ecx,7
			
			lea eax,[ecx+32]
			push eax
			call dword ptr [ecx-4]

			popfd
			popad
			ret
	}
}

DWORD WINAPI stub_end()
{
	return 0;
}

int ContextInject(HANDLE hProcess, HANDLE hThread)
{
	CONTEXT ctx;
	DWORD mem;

	printf("Attempting Injection via thread context hijacking...\n");

	ctx.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(hThread, &ctx))
	{
		printf("Cannot get thread context: %d", GetLastError());
		return -1;
	}

	mem = WriteStubEx(hProcess);

	// decrement stack pointer and write EIP to the stack
	ctx.Esp -= 4;
	WriteProcessMemory(hProcess, (PVOID)ctx.Esp, &ctx.Eip, sizeof(PVOID), NULL);

	// set instruction pointer to the stub code
	ctx.Eip = mem;

	if (!SetThreadContext(hThread, &ctx))
	{
		printf("SetThreadContext failed: %d", GetLastError());
		return -1;
	}

	ResumeThread(hThread);

	return 0;
}

int ApcInject(HANDLE hProcess, HANDLE hThread)
{
	DWORD mem;
	NT_QUEUE_APC_THREAD NtQueueApcThread = (NT_QUEUE_APC_THREAD)(GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueueApcThread"));

	printf("Attempting Injection using NtQueueApcThread...\n");

	mem = WriteStubEx(hProcess);

	NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)mem, NULL, NULL, NULL);
	printf("NtQueueApcThread called: %d\n", GetLastError());

	ResumeThread(hThread);

	return 0;
}

int RemoteThreadInject(HANDLE hProcess, HANDLE hThread)
{
	DWORD mem;

	printf("Attempting Injection using CreateRemoteThread...\n");

	mem = WriteStubEx(hProcess);

	if (!CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL))
	{
		printf("CreateRemoteThread failed :(\n");
	}

	ResumeThread(hThread);

	return 0;
}

DWORD WriteStubEx(HANDLE hProcess)
{
	DWORD stublen;
	PVOID LoadLibAddr, mem;
	char* dllname = "InjectMe.dll";

	stublen = (DWORD)stub_end - (DWORD)stub; // length of shellcode
	LoadLibAddr = LoadLibraryA;

	// Allocate memory in the process
	mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	printf("Memory allocated at 0x%x\nAbout to write stub code...\n", mem);

	// Write LoadLibrary address. Will fail if using ASLR. Can remedy this with shellcode that works
	// out the address using PEB.InOrderModuleList.	
	WriteProcessMemory(hProcess, mem, &LoadLibAddr, sizeof(PVOID), NULL);
	// Write shellcode
	WriteProcessMemory(hProcess, (LPVOID)((LPBYTE)mem + 4), stub, stublen, NULL);
	// Write dll string
	WriteProcessMemory(hProcess, (LPVOID)((LPBYTE)mem + 4 + stublen), dllname, strlen(dllname), NULL);

	return (DWORD)((LPBYTE)mem + 4); // return the start of the shellcode
}

int _tmain(int argc, _TCHAR* argv[])
{
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION procInfo;

	memset(&startupInfo, 0, sizeof(startupInfo));
	memset(&procInfo, 0, sizeof(procInfo));

	startupInfo.cb = sizeof(startupInfo);

	if (argc == 1)
	{
		printf("Argument please...\n\n\t0 : Context Hijacking\n\t1 : NtQueueApcThread\n\t2 : CreateRemoteThread\n");
		return -1;
	}

	CreateProcess(
		L"C:\\Windows\\SysWOW64\\svchost.exe", 
		NULL,
		NULL, 
		NULL, 
		TRUE, 
		CREATE_SUSPENDED,
		NULL, 
		NULL, 
		&startupInfo, 
		&procInfo);

	printf("Process started. Pid %x\n", procInfo.dwProcessId);

	switch (_wtoi(argv[1]))
	{
	case 0:
		ContextInject(procInfo.hProcess, procInfo.hThread);
		break;
	case 1:
		ApcInject(procInfo.hProcess, procInfo.hThread);
		break;
	case 2:
		RemoteThreadInject(procInfo.hProcess, procInfo.hThread);
		break;
	default:
		printf("Invalid argument");
		break;
	}

	return 0;
}