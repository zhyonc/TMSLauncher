#pragma once
#include <string>
#include <windows.h>

#define DEBUG(msg) \
{\
std::wstring wmsg = L"[Debug] ";\
wmsg += msg;\
OutputDebugStringW(wmsg.c_str());\
}

std::wstring BYTEtoString(BYTE b);
#ifdef _WIN64
std::wstring QWORDtoString(ULONG_PTR u, bool slim = false);
#define SCANRES(msg) DEBUG(L""#msg" = " + QWORDtoString(msg))
#else
std::wstring DWORDtoString(DWORD dw);
#define SCANRES(msg) DEBUG(L""#msg" = " + DWORDtoString(msg))
#endif