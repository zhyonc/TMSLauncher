#include "Injector.h"
#include <string>
#include <iostream>

#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#ifndef _WIN64
#define DLL_NAME L"Hook.dll"
#else
#define DLL_NAME L"Hook64.dll"
#endif

#define SERVER_IP L"127.0.0.1"


bool PathExists(const std::wstring& path) {
	return PathFileExists(path.c_str()) == TRUE;
}

std::wstring GetExecutablePath() {
	WCHAR path[MAX_PATH];
	GetModuleFileNameW(NULL, path, MAX_PATH);
	return std::wstring(path);
}

std::wstring GetExecutableDir() {
	std::wstring executablePath = GetExecutablePath();
	size_t pos = executablePath.find_last_of(L"\\/");
	return (std::wstring::npos == pos) ? L"" : executablePath.substr(0, pos);
}

int main() {
	FreeConsole();
	std::wstring exeDir = GetExecutableDir();
	if (exeDir == L"") {
		MessageBox(NULL, L"Unable to get executalbe directory", L"Launcher", MB_OK | MB_ICONERROR);
		return 1;
	}
	std::wstring wTargetPath = exeDir + L"\\" + L"MapleStory.exe";
	std::wstring wDllPath = exeDir + L"\\" + DLL_NAME;
	if (!PathExists(wTargetPath)) {
		MessageBox(NULL, L"Please run in MapleStory directory", L"Launcher", MB_OK | MB_ICONINFORMATION);
		return 1;
	}
	if (!PathExists(wDllPath)) {
		std::wstring msg = L"Can't find file " + std::wstring(DLL_NAME);
		MessageBox(NULL, msg.c_str(), L"Launcher", MB_OK | MB_ICONERROR);
		return 1;
	}
	Injector injector(wTargetPath, wDllPath);
	std::wstring wServerAddr = L" ";
	wServerAddr.append(SERVER_IP).append(L" 8484");
	if (!injector.Run(wServerAddr)) {
		MessageBox(NULL, L"Unable to inject dll into target", L"Launcher", MB_OK | MB_ICONERROR);
		return 1;
	};
	return 0;
}