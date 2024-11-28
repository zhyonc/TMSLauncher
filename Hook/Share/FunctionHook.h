#pragma once
#include <windows.h>
#include <vector>
// hook internal
class FunctionHook {
private:
	void* Memory;
	ULONG_PTR MemorySize;
	ULONG_PTR HookAddress;
	bool bHooked;
#ifndef _WIN64
#define JMP_OPCODE_SIZE_SHORT 2
#define JMP_OPCODE_SIZE_LONG 5
#define HOT_PATCH_SIZE 5
#else
	//#define JMP_OPCODE_SIZE 14
#define JMP_OPCODE_SIZE_SHORT 6
#define JMP_OPCODE_SIZE_LONG 14
#define HOT_PATCH_SIZE 8
#endif
	FunctionHook(const FunctionHook&) = delete;
	void operator=(const FunctionHook&) = delete;

	static void Redirection(ULONG_PTR& dwEIP);

	static bool DecodeInit();

	static ULONG_PTR Decode(ULONG_PTR uStartAddress, bool bHotPatch);

	static bool HotPatch(ULONG_PTR uHookAddress, ULONG_PTR& uHotPatch);

public:
	// Inline Hook
	FunctionHook(void* HookFunction, ULONG_PTR Address, DWORD dwStackValue);
	FunctionHook(void* HookFunction, void* FunctionPointer, ULONG_PTR Address, ULONG_PTR OverWrite);
	~FunctionHook();

	static ULONG_PTR Decode(ULONG_PTR uStartAddress);

	static ULONG_PTR Decode(ULONG_PTR uStartAddress, std::vector<BYTE>& vCodeSize, ULONG_PTR uMinimumSize);

	bool IsHooked();
};