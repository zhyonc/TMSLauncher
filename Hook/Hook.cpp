#include "Hook.h"
#include "CRC.h"
#include "Auth.h"
#include "Share/FunctionHookList.h"
#include<intrin.h>
#pragma intrinsic(_ReturnAddress)

#define WINDOW_TITLE "goms"

void HookStartupInfoA() {
	static auto _GetStartupInfoA = (decltype(&GetStartupInfoA))(GetProcAddress(GetModuleHandleW(L"KERNEL32"), "GetStartupInfoA"));
	decltype(&GetStartupInfoA) Hook = [](LPSTARTUPINFOA lpStartupInfo) -> void
		{
			if (lpStartupInfo && FunctionHookList::IsCallerEXE(_ReturnAddress())) {
				Rosemary r;
				ResolveDomain(r);
				if (!RemoveCRC(r)) {
					DEBUG(L"Unable to remove CRC");
				};
				if (!RemoveHS(r)) {
					DEBUG(L"Unable to remove HS");
				};
				if (!RemoveX3(r)) {
					DEBUG(L"Unable to remove X3");
				};
	
			}
			_GetStartupInfoA(lpStartupInfo);
		};
	FunctionHookList::Add(Hook, (void**)&_GetStartupInfoA, (ULONG_PTR)_GetStartupInfoA);
}


void HookCreateWindowExA()
{
	static auto _CreateWindowExA = decltype(&CreateWindowEx)(GetProcAddress(GetModuleHandleW(L"USER32"), "CreateWindowExA"));
	decltype(&CreateWindowEx) Hook = [](DWORD dwExStyle, LPCTSTR lpClassName, LPCTSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam) -> HWND
		{
			auto lpLocalWndName = lpWindowName;
			// Advanced->Character Set->Use Multi-Byte
			if (!strcmp(lpClassName, "StartUpDlgClass"))
			{
				return NULL;
			}
			else if (!strcmp(lpClassName, "NexonADBallon"))
			{
				return NULL;
			}
			else if (!strcmp(lpClassName, "MapleStoryClass"))
			{
				lpLocalWndName = WINDOW_TITLE;
			}

			return _CreateWindowExA(dwExStyle, lpClassName, lpLocalWndName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
		};

	FunctionHookList::Add(Hook, (void**)&_CreateWindowExA, (ULONG_PTR)_CreateWindowExA);
}

void HookCreateMutexA()
{
	static auto _CreateMutexA = decltype(&CreateMutexA)(GetProcAddress(GetModuleHandleW(L"KERNEL32"), "CreateMutexA"));
	decltype(&CreateMutexA) Hook = [](LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName) -> HANDLE
		{
			if (lpName && !strcmp(lpName, "WvsClientMtx"))
			{
				// MultiClient: faking HANDLE and name it bad food
				return (HANDLE)0xBADF00D;
			}

			return _CreateMutexA(lpMutexAttributes, bInitialOwner, lpName);
		};
	FunctionHookList::Add(Hook, (void**)&_CreateMutexA, (ULONG_PTR)_CreateMutexA);
}

// Unuse
void UnHook() {
	bool res = FunctionHookList::Remove();
	if (!res) {
		DEBUG(L"Failed to clear FunctionHookList");
	}
}