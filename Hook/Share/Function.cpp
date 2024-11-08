#include "Function.h"
#include "Config.h"
#include <fstream>
#include <vector>
#include <tlhelp32.h>
#include <detours.h>
#pragma comment(lib, "detours.lib")


#define JMP		0xE9
#define NOP		0x90
#define RET		0xC3

#define relative_address(frm, to) (int)(((int)to - (int)frm) - 5)

void Log(const char* format, ...) {
	if (!OPT_ENABLE_LOG) {
		return;
	}
	char buf[1024] = { 0 };
	va_list args;
	va_start(args, format);
	vsprintf_s(buf, format, args);
	std::fstream file;
	file.open("hook.txt", std::ios::out | std::ios::app);
	if (file.is_open()) {
		file << buf << std::endl;
		file.close();
	}
}

std::vector<MEMORY_BASIC_INFORMATION> section_list;

// Wait exe memory expansion before dll hook
bool InitSectionInformation() {
	DWORD pid = GetCurrentProcessId();

	if (!pid) {
		return false;
	}

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return false;
	}

	MODULEENTRY32W me;
	memset(&me, 0, sizeof(me));
	me.dwSize = sizeof(me);
	if (!Module32FirstW(hSnapshot, &me)) {
		return false;
	}

	std::vector<MODULEENTRY32W> module_list;
	do {
		module_list.push_back(me);
	} while (Module32NextW(hSnapshot, &me));

	CloseHandle(hSnapshot);

	// first module may be exe
	if (module_list.size() < 0) {
		return false;
	}

	MEMORY_BASIC_INFORMATION mbi;
	memset(&mbi, 0, sizeof(mbi));

	ULONG_PTR section_base = (ULONG_PTR)module_list[0].modBaseAddr;

	while (section_base < ((ULONG_PTR)module_list[0].modBaseAddr + module_list[0].modBaseSize) && (VirtualQuery((void*)section_base, &mbi, sizeof(mbi)) == sizeof(mbi))) {
		section_list.push_back(mbi);
		section_base += mbi.RegionSize;
	}

	if (!section_list.size()) {
		return false;
	}

	return true;
}

int IsCallerEXE(void* vReturnAddress) {
	// init
	if (section_list.size() == 0) {
		InitSectionInformation();
	}

	// check addresss
	for (size_t i = 0; i < section_list.size(); i++) {
		if ((ULONG_PTR)section_list[i].BaseAddress <= (ULONG_PTR)vReturnAddress && (ULONG_PTR)vReturnAddress <= ((ULONG_PTR)section_list[i].BaseAddress + section_list[i].RegionSize)) {
			return (int)i;
		}
	}

	return 0;
}

BOOL SetHook(BOOL bInstall, PVOID* ppvTarget, PVOID pvDetour)
{
	if (DetourTransactionBegin() != NO_ERROR)
	{
		return FALSE;
	}

	auto tid = GetCurrentThread();

	if (DetourUpdateThread(tid) != NO_ERROR) {
		DetourTransactionAbort();
		return FALSE;
	}

	auto func = bInstall ? DetourAttach : DetourDetach;
	if (func(ppvTarget, pvDetour) != NO_ERROR) {
		DetourTransactionAbort();
		return FALSE;
	}

	if (DetourTransactionCommit() != NO_ERROR) {
		DetourTransactionAbort();
		return FALSE;
	}
	return TRUE;
}

DWORD GetFuncAddress(LPCSTR lpModule, LPCSTR lpFunc)
{
	auto mod = LoadLibraryA(lpModule);

	if (!mod)
	{
		return 0;
	}

	auto address = (DWORD)GetProcAddress(mod, lpFunc);

	if (!address)
	{
		return 0;
	}

#ifdef _DEBUG
	Log(__FUNCTION__" [%s] %s @ %8X", lpModule, lpFunc, address);
#endif
	return address;
}

void PatchJmp(DWORD dwAddress, DWORD dwDest)
{

	*(BYTE*)dwAddress = JMP;
	*(DWORD*)(dwAddress + 1) = relative_address(dwAddress, dwDest);
}

void PatchRetZero(DWORD dwAddress)
{
	*(BYTE*)(dwAddress + 0) = 0x33;
	*(BYTE*)(dwAddress + 1) = 0xC0;
	*(BYTE*)(dwAddress + 2) = RET;
}