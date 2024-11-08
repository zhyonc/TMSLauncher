#include "Rosemary.h"
#include "AobScan.h"
#include "Code.h"

Rosemary::Rosemary() {
	init = GetSections(L"MapleStory.exe", true);
}

Rosemary::Rosemary(std::wstring wModuleName) {
	init = GetSections(wModuleName);
}

Rosemary::~Rosemary() {

}

bool Rosemary::IsInitialized() const {
	return init;
}

bool Rosemary::GetSections(std::wstring wModuleName, bool bExe) {
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

	for (size_t i = 0; i < module_list.size(); i++) {
		if (bExe || _wcsicmp(module_list[i].szModule, wModuleName.c_str()) == 0) {
			MEMORY_BASIC_INFORMATION mbi;
			memset(&mbi, 0, sizeof(mbi));

			ULONG_PTR section_base = (ULONG_PTR)module_list[i].modBaseAddr;
			while (section_base < ((ULONG_PTR)module_list[i].modBaseAddr + module_list[i].modBaseSize) && (VirtualQuery((void*)section_base, &mbi, sizeof(mbi)) == sizeof(mbi))) {
				if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
					section_list.push_back(mbi);
				}
				// data section for string search
				if (section_list.size() && mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY)) { // PAGE_READONLY and EXECUTE are currently ignored
					data_section_list.push_back(mbi);
				}
				section_base += mbi.RegionSize;
			}

			if (!section_list.size()) {
				return false;
			}

			return true;
		}
	}

	return false;
}

ULONG_PTR Rosemary::Scan(std::wstring wAob, int res) {
	if (!init) {
		return 0;
	}

	AobScan a(wAob);

	int count = 0;
	for (size_t i = 0; i < section_list.size(); i++) {
		for (ULONG_PTR uAddress = (ULONG_PTR)section_list[i].BaseAddress; uAddress < ((ULONG_PTR)section_list[i].BaseAddress + section_list[i].RegionSize); uAddress++) {
			if (a.Compare(uAddress)) {
				count++;
				if (res) {
					if (res != count) {
						continue;
					}
				}
				return uAddress;
			}
		}
	}

	return 0;
}

// ListScan
ULONG_PTR Rosemary::Scan(std::wstring wAobList[], size_t size, size_t& index, bool(*Scanner)(ULONG_PTR)) {
	ULONG_PTR uAddress = 0;

	index = -1;

	if (!init) {
		return 0;
	}

	for (size_t i = 0; i < size; i++) {

		if (!Scanner) {
			uAddress = Scan(wAobList[i]);
		}
		else {
			uAddress = Scan(wAobList[i], Scanner);
		}

		if (uAddress) {
			index = i;
			return uAddress;
		}
	}

	return 0;
}


ULONG_PTR Rosemary::Scan(std::wstring wAob, bool(*Scanner)(ULONG_PTR)) {
	if (!init) {
		return 0;
	}

	if (!Scanner) {
		return 0;
	}

	AobScan a(wAob);

	for (size_t i = 0; i < section_list.size(); i++) {
		for (ULONG_PTR uAddress = (ULONG_PTR)section_list[i].BaseAddress; uAddress < ((ULONG_PTR)section_list[i].BaseAddress + section_list[i].RegionSize); uAddress++) {
			if (a.Compare(uAddress)) {
				if (Scanner(uAddress)) {
					return uAddress;
				}
			}
		}
	}

	return 0;
}

bool Rosemary::Patch(std::wstring wAob, std::wstring wCode) {
	ULONG_PTR uAddress = Scan(wAob);

	if (!uAddress) {
		return false;
	}

	Code c(wCode);
	return c.Write(uAddress);
}

bool Rosemary::Patch(ULONG_PTR uAddress, std::wstring wCode) {
	if (!uAddress) {
		return false;
	}

	Code c(wCode);
	return c.Write(uAddress);
}

bool Rosemary::Backup(std::vector<MEMORY_BASIC_INFORMATION>& vSection, std::vector<void*>& vBackup) {
	vSection.clear();
	vBackup.clear();

	if (!init) {
		return false;
	}

	for (size_t i = 0; i < section_list.size(); i++) {
		void* memory = VirtualAlloc(NULL, section_list[i].RegionSize, MEM_COMMIT, PAGE_READWRITE);
		if (!memory) {
			vBackup.clear();
			return false;
		}
		for (size_t j = 0; j < section_list[i].RegionSize; j++) {
			// Ensure j does not exceed buffer size
			if (j >= section_list.size()) {
				break;  // Prevent buffer overrun
			}
			((BYTE*)memory)[j] = *(BYTE*)((ULONG_PTR)section_list[i].BaseAddress + j);
		}
		vBackup.push_back(memory);
	}

	vSection = section_list;
	return true;
}

bool Rosemary::Hook(ULONG_PTR uAddress, void* HookFunction, ULONG_PTR uNop) {
	DWORD old = 0;
	if (!VirtualProtect((void*)uAddress, 5 + uNop, PAGE_EXECUTE_READWRITE, &old)) {
		return false;
	}

	*(BYTE*)uAddress = 0xE9;
	*(DWORD*)(uAddress + 0x01) = (DWORD)((ULONG_PTR)HookFunction - uAddress) - 0x05;

	for (size_t i = 0; i < uNop; i++) {
		((BYTE*)uAddress)[5 + i] = 0x90;
	}

	VirtualProtect((void*)uAddress, 5 + uNop, old, &old);
	return true;
}

bool Rosemary::JMP(ULONG_PTR uPrev, ULONG_PTR uNext, ULONG_PTR uNop) {
	DWORD old = 0;
	if (!VirtualProtect((void*)uPrev, 5 + uNop, PAGE_EXECUTE_READWRITE, &old)) {
		return false;
	}

	*(BYTE*)uPrev = 0xE9;
	*(DWORD*)(uPrev + 0x01) = (DWORD)(uNext - uPrev) - 0x05;

	for (size_t i = 0; i < uNop; i++) {
		((BYTE*)uPrev)[5 + i] = 0x90;
	}

	VirtualProtect((void*)uPrev, 5 + uNop, old, &old);
	return true;
}

bool Rosemary::GetSectionList(std::vector<MEMORY_BASIC_INFORMATION>& vSection) {
	vSection = section_list;
	return true;
}

ULONG_PTR Rosemary::StringPatch(std::string search_string, std::string replace_string) {
	// including null
	size_t search_string_size = search_string.length() + 1;
	size_t replace_string_size = replace_string.length() + 1;

	if (search_string_size < replace_string_size) {
		// unsafe
		return 0;
	}
	for (size_t i = 0; i < data_section_list.size(); i++) {
		for (ULONG_PTR uAddress = (ULONG_PTR)data_section_list[i].BaseAddress; uAddress < ((ULONG_PTR)data_section_list[i].BaseAddress + data_section_list[i].RegionSize - search_string_size); uAddress++) {
			if (memcmp((void*)uAddress, search_string.c_str(), search_string_size) == 0) {
				memset((void*)uAddress, 0, search_string_size);
				memcpy_s((void*)uAddress, replace_string_size, replace_string.c_str(), replace_string_size);
				return uAddress;
			}
		}
	}
	// some packer's has execute flags
	for (size_t i = 0; i < section_list.size(); i++) {
		for (ULONG_PTR uAddress = (ULONG_PTR)section_list[i].BaseAddress; uAddress < ((ULONG_PTR)section_list[i].BaseAddress + section_list[i].RegionSize - search_string_size); uAddress++) {
			if (memcmp((void*)uAddress, search_string.c_str(), search_string_size) == 0) {
				memset((void*)uAddress, 0, search_string_size);
				memcpy_s((void*)uAddress, replace_string_size, replace_string.c_str(), replace_string_size);
				return uAddress;
			}
		}
	}
	return 0;
}