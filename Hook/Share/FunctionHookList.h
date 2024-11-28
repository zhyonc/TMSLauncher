#pragma once
#include <windows.h> 

namespace FunctionHookList {
	bool Add(void* HookFunction, void* FunctionPointer, ULONG_PTR Address, ULONG_PTR OverWrite = 0);
	bool Remove();
	bool InitSectionInformation();
	int IsCallerEXE(void* vReturnAddress);
}
