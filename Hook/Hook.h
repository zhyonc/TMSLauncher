#pragma once
#include "Share/FunctionHookList.h"
#include <string>

#define DEBUG(msg) \
{\
std::wstring wmsg = L"[Debug] ";\
wmsg += msg;\
OutputDebugStringW(wmsg.c_str());\
}

void HookStartupInfoA();
void HookCreateWindowExA();
void HookCreateMutexA();
void UnHook();
