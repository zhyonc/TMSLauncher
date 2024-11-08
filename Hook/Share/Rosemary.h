
#pragma once
#include <vector>
#include <string>
#include <windows.h>
#include <tlhelp32.h>

class Rosemary {
private:
	bool init;
	std::vector<MEMORY_BASIC_INFORMATION> section_list;
	std::vector<MEMORY_BASIC_INFORMATION> data_section_list;
	bool GetSections(std::wstring wModuleName, bool bExe = false);

public:
	Rosemary();
	Rosemary(std::wstring wModuleName);
	~Rosemary();
	bool IsInitialized() const;
	ULONG_PTR Scan(std::wstring wAob, int res = 0);
	ULONG_PTR Scan(std::wstring wAobList[], size_t size, size_t& index, bool(*Scanner)(ULONG_PTR) = NULL);
	ULONG_PTR Scan(std::wstring wAob, bool (*Scanner)(ULONG_PTR));
	bool Patch(std::wstring wAob, std::wstring wCode);
	bool Patch(ULONG_PTR uAddress, std::wstring wCode);
	bool Backup(std::vector<MEMORY_BASIC_INFORMATION>& vSection, std::vector<void*>& vBackup);
	bool JMP(ULONG_PTR uPrev, ULONG_PTR uNext, ULONG_PTR uNop = 0);
	bool Hook(ULONG_PTR uAddress, void* HookFunction, ULONG_PTR uNop = 0);
	bool GetSectionList(std::vector<MEMORY_BASIC_INFORMATION>& vSection);
	// test
	ULONG_PTR StringPatch(std::string search_string, std::string replace_string);
};