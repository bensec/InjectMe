// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	char *eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
	HANDLE hFile = NULL;
	BOOL bErrorFlag;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		OutputDebugString(TEXT("InjectMe: Dll attached"));
		MessageBox(NULL, L"InjectMe: Dll attached", L"Moo", 0);

		hFile = CreateFile(L"eicar.com", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile == INVALID_HANDLE_VALUE)
		{
			MessageBox(NULL, L"Invalid file handle!", L"Moo", 0);
			break;
		}
		else
		{
			OutputDebugString(TEXT("CreateFile success"));
		}

		bErrorFlag = WriteFile(hFile, eicar, strlen(eicar), NULL, NULL);

		if (!bErrorFlag)
		{
			MessageBox(NULL, L"WriteFile failed!", L"Moo", 0);
			break;
		}
		else
		{
			OutputDebugString(TEXT("WriteFile success!"));
		}

		CloseHandle(hFile);
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

