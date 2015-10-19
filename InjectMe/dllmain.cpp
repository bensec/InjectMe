// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		OutputDebugString(TEXT("InjectMe: Dll attached"));
		MessageBox(NULL, L"InjectMe: Dll attached", L"Moo", 0);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		OutputDebugString(TEXT("InjectMe: Dll detached"));
		MessageBox(NULL, L"InjectMe: Dll detached", L"Moo", 0);
		break;
	default:
		break;
	}
	return TRUE;
}

