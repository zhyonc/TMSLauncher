#pragma once
#include <Windows.h>

void Log(const char* format, ...);
bool InitSectionInformation();
int IsCallerEXE(void* vReturnAddress);
BOOL SetHook(BOOL bInstall, PVOID* ppvTarget, PVOID pvDetour);
DWORD GetFuncAddress(LPCSTR lpModule, LPCSTR lpFunc);
void PatchRetZero(DWORD dwAddress);
void PatchJmp(DWORD dwAddress, DWORD dwDest);
