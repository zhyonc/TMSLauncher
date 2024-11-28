// for macro
#include <windows.h>
#include <tlhelp32.h>
#include "FunctionHookList.h"
#include "FunctionHook.h"

namespace FunctionHookList {
	std::vector<FunctionHook*> HookList;
	bool Add(void* HookFunction, void* FunctionPointer, ULONG_PTR Address, ULONG_PTR OverWrite) {
		HookList.push_back(new FunctionHook(HookFunction, FunctionPointer, Address, OverWrite));
		return HookList.back()->IsHooked();
	}

	bool InlineHook(void* HookFunction, ULONG_PTR Address, DWORD dwStackValue) {
		HookList.push_back(new FunctionHook(HookFunction, Address, dwStackValue));
		return HookList.back()->IsHooked();
	}

	bool Remove() {
		for (size_t i = 0; i < HookList.size(); i++) {
			delete HookList[i];
		}
		HookList.clear();
		return true;
	}

	bool Analyze(ULONG_PTR uAddress, std::vector<BYTE>& vCodeSize, ULONG_PTR uMinimumSize) {
		if (!FunctionHook::Decode(uAddress, vCodeSize, uMinimumSize)) {
			return false;
		}

		return true;
	}

	// test
	std::vector<MEMORY_BASIC_INFORMATION> section_list;

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
}