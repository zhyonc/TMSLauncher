#include "Hook.h"
#include "Play.h"
#include "Auth.h"
#include "CRC.h"
#include "Tool.h"
#include "AobList.h"
#include "Share/FunctionHookList.h"

#include<intrin.h>
#pragma intrinsic(_ReturnAddress)

#define WINDOW_TITLE "goms"

bool bAlreadyLoaded = false;
void HookStartupInfoA() {
	static auto _GetStartupInfoA = (decltype(&GetStartupInfoA))(GetProcAddress(GetModuleHandleW(L"KERNEL32"), "GetStartupInfoA"));
	decltype(&GetStartupInfoA) Hook = [](LPSTARTUPINFOA lpStartupInfo) -> void
		{
			if (lpStartupInfo && FunctionHookList::IsCallerEXE(_ReturnAddress())) {
				if (bAlreadyLoaded) {
					return;
				}
				// Set bAlreadyLoadedAvoid true to prevent the client from getting stuck when RemoveCRC
				bAlreadyLoaded = true;
				Rosemary r;
				FixPlay(r);
				FixWindowMode(r);
				if (!RemoveCRC(r)) {
					DEBUG(L"Unable to remove CRC");
				};
				if (!RemoveAntiCheat(r)) {
					DEBUG(L"Unable to remove AntiCheat");
				}
				else {
					HookSendWvsSetUpStep(r);
				}
			}

			return _GetStartupInfoA(lpStartupInfo);
		};
	FunctionHookList::Add(Hook, &_GetStartupInfoA, (ULONG_PTR)_GetStartupInfoA);
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

	FunctionHookList::Add(Hook, &_CreateWindowExA, (ULONG_PTR)_CreateWindowExA);
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
	FunctionHookList::Add(Hook, &_CreateMutexA, (ULONG_PTR)_CreateMutexA);
}

// Not used
void UnHook() {
	bool res = FunctionHookList::Remove();
	if (!res) {
		DEBUG(L"Failed to clear FunctionHookList");
	}
}