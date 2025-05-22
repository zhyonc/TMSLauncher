#include "Hook.h"
#include "Config.h"
#include "Socket.h"
#include "ImgFile.h"
#include "Auth.h"
#include "CRC.h"
#include "Screen.h"
#include "Tool.h"

#include "Share/Funcs.h"

#include<intrin.h>
#pragma intrinsic(_ReturnAddress)

namespace {
	static Rosemary gMapleR;
	static bool bGetStartupInfoALoaded = false;
	static bool bCreateWindowExALoaded = false;
	static bool bCreateMutexALoaded = false;

	void GetMoudleEntryList(std::vector<MODULEENTRY32W>& entryList) {
		DWORD pid = GetCurrentProcessId();

		if (!pid) {
			return;
		}

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

		if (hSnapshot == INVALID_HANDLE_VALUE) {
			return;
		}

		MODULEENTRY32W me32;
		memset(&me32, 0, sizeof(me32));
		me32.dwSize = sizeof(me32);
		if (!Module32FirstW(hSnapshot, &me32)) {
			CloseHandle(hSnapshot);
			return;
		}

		entryList.clear();

		do {
			entryList.push_back(me32);
		} while (Module32NextW(hSnapshot, &me32));

		CloseHandle(hSnapshot);
	}

	// Make sure the executable unpacks itself.
	bool IsEXECaller(void* vReturnAddress) {
		if (gMapleR.IsInitialized()) {
			DEBUG(L"gMapleR has already been initialized");
			return true;
		}
		std::vector<MODULEENTRY32W> entryList;
		GetMoudleEntryList(entryList);
		if (entryList.empty()) {
			DEBUG(L"EXE hasn't been call yet");
			return false;
		}
		// first module may be exe
		const MODULEENTRY32W& me32 = entryList[0];
		ULONG_PTR returnAddr = (ULONG_PTR)vReturnAddress;
		ULONG_PTR baseAddr = (ULONG_PTR)me32.modBaseAddr;
		ULONG_PTR endAddr = baseAddr + me32.modBaseSize;

		if (returnAddr >= baseAddr && returnAddr < endAddr) {
			gMapleR.Init(&entryList, L"MapleStory.exe");
			if (gMapleR.IsInitialized()) {
				DEBUG(L"gMapleR init ok");
				return true;
			}
			else {
				DEBUG(L"Failed to init gMapleR");
				return false;
			}
		}
		return false;
	}

	// 1.FixDomain: Unable show ad window if not set
	// 2.RemoveLocaleCheck(option): For other locale
	// 3.Redirect: Modify connect ip and port
	// 4.SendConnectKey(option): Avoid using cmd start client
	// 5.RecvXOR(option): XOR all packet from server
	// 6.RemoveAntiCheat: NGS/HS/X3
	// 7.MountImgFile: Convert wz file to img format
	// 8.FixWindowMode(option): Avoid old client can't run with recent displays
	// 9.RemoveCRC: Avoid client crash after 30s or enter field
	static auto _GetStartupInfoA = decltype(&GetStartupInfoA)(GetProcAddress(GetModuleHandleW(L"KERNEL32"), "GetStartupInfoA"));
	VOID WINAPI GetStartupInfoA_Hook(LPSTARTUPINFOA lpStartupInfo) {
		if (lpStartupInfo && !bGetStartupInfoALoaded && IsEXECaller(_ReturnAddress())) {
			bGetStartupInfoALoaded = true;
			// Click MapleStory.exe
			if (!Screen::FixDomain(gMapleR)) {
				DEBUG(L"Unable to fix domain");
			}
			if (!Auth::RemoveLocaleCheck(gMapleR)) {
				DEBUG(L"Unable to remove locale check");
			}
			// Click Play button
			if (!Socket::InitWSAData()) {
				DEBUG(L"Unable to init WSAData");
			}
			if (Config::IsSendConnectKey) {
				Socket::SetConnectKey(Config::ConnectKey);
			}
			if (!Socket::Redirect(Config::ChannelServerAddr, Config::LoginServerAddr, Config::LoginServerPort)) {
				DEBUG(L"Unable to redirect the connection");
			}
			if (Config::IsRecvXOR) {
				if (!Socket::RecvXOR(Config::RecvXOR)) {
					DEBUG(L"Unable to hook recv");
				}
			}
			// Load AntiCheat 
			if (!Auth::RemoveAntiCheat(gMapleR)) {
				DEBUG(L"Unable to remove AntiCheat");
			}
			// Load wz file
			if (Config::IsImgFile) {
				if (!ImgFile::Mount(gMapleR)) {
					DEBUG(L"Unable to mount img file");
				}
			}
			// Game window is loaded
			if (!Screen::FixWindowMode(gMapleR)) {
				DEBUG(L"Unable to fix window mode");
			}
			// Login UI is loaded
			if (!CRC::RemoveRenderFrameCheck(gMapleR)) {
				DEBUG(L"Unable to remove Render Frame Check");
			}
			// Select character
			if (!CRC::RemoveCWvsContextOnEnterFieldCheck(gMapleR)) {
				DEBUG(L"Unable to remove Enter Field Check");
			}
		}
		_GetStartupInfoA(lpStartupInfo);
	}

	static auto _CreateWindowExA = decltype(&CreateWindowEx)(GetProcAddress(GetModuleHandleW(L"USER32"), "CreateWindowExA"));
	HWND WINAPI CreateWindowExA_Hook(DWORD dwExStyle, LPCTSTR lpClassName, LPCTSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam) {
		// AoB 68 00 00 04 80
		if (lpClassName && strstr(lpClassName, "StartUpDlgClass")) {
			// Found in ShowADBalloon 
			return NULL;
		}
		if (lpClassName && strstr(lpClassName, "MapleStoryClass")) {
			// Found in ShowStartUpWnd
			lpWindowName = Config::WindowTitle.c_str(); //Customize game windowtitle 	
			Screen::FixMinimizeButton(dwStyle); // Show minimize button for TMS113 - TMS118
		}

		return _CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
	}

	// CreateMutexA is the first Windows library call after the executable unpacks itself. 
	// It is recommended to have all Maple hooking and memory editing inside or called from the CreateMutexA function.
	static auto _CreateMutexA = decltype(&CreateMutexA)(GetProcAddress(GetModuleHandleW(L"KERNEL32"), "CreateMutexA"));
	HANDLE WINAPI CreateMutexA_Hook(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName) {
		if (!bCreateMutexALoaded) {
			bCreateMutexALoaded = true;
			// TODO

		}
		if (Config::IsMultipleClient) {
			// Put this condition at the bottom
			if (lpName && strstr(lpName, "WvsClientMtx")) {
				// MultiClient: faking HANDLE is 0xBADF00D(BadFood)
				return (HANDLE)0xBADF00D;
			}
		}
		return _CreateMutexA(lpMutexAttributes, bInitialOwner, lpName);
	}

}

namespace Hook {
	void Install() {
		bool ok = SHOOK(true, &_GetStartupInfoA, GetStartupInfoA_Hook) &&
			SHOOK(true, &_CreateWindowExA, CreateWindowExA_Hook) &&
			SHOOK(true, &_CreateMutexA, CreateMutexA_Hook);
		if (!ok) {
			DEBUG(L"Failed to install hook");
		}
	}

	void Uninstall() {
		bool ok = SHOOK(false, &_GetStartupInfoA, GetStartupInfoA_Hook) &&
			SHOOK(false, &_CreateWindowExA, CreateWindowExA_Hook) &&
			SHOOK(false, &_CreateMutexA, CreateMutexA_Hook);
		if (!ok) {
			DEBUG(L"Failed to uninstall hook");
		}
		Socket::ClearupWSA();
	}
}
