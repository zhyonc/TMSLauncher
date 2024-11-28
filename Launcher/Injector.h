#pragma once
#include <windows.h>
#include <string>

class Injector {
private:
	PROCESS_INFORMATION target_pi;
	std::wstring target_path;
	std::wstring dll_path;
	HANDLE process_handle;
	HANDLE main_thread_handle;
	bool is_successed;

public:
	Injector(std::wstring wTargetPath, std::wstring wDllPath);
	Injector(PROCESS_INFORMATION& pi, std::wstring wDllPath);
	~Injector();
	HANDLE GetProcessHandle();
	bool Run(std::wstring wCmdLine = L"");
	bool Inject();
};
