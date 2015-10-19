// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <Windows.h>

typedef void (CALLBACK *PKNORMAL_ROUTINE)(PVOID, PVOID, PVOID);
typedef NTSTATUS(__stdcall *NT_QUEUE_APC_THREAD)(HANDLE, PKNORMAL_ROUTINE, PVOID, PVOID, PVOID);

// TODO: reference additional headers your program requires here
int ContextInject(HANDLE hProcess, HANDLE hThread);
int ApcInject(HANDLE hProcess, HANDLE hThread);
int RemoteThreadInject(HANDLE hProcess, HANDLE hThread);
DWORD WriteStubEx(HANDLE hProcess);
