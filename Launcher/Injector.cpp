#include "Injector.h"

Injector::Injector(std::wstring wTargetPath, std::wstring wDllPath) {
	target_path = wTargetPath;
	dll_path = wDllPath;
	process_handle = NULL;
	main_thread_handle = NULL;
	is_successed = false;
	memset(&target_pi, 0, sizeof(target_pi));
};

Injector::Injector(PROCESS_INFORMATION& pi, std::wstring wDllPath) {
	dll_path = wDllPath;
	process_handle = NULL;
	main_thread_handle = NULL;
	is_successed = false;
	target_pi = pi;
}

Injector::~Injector() {
	if (main_thread_handle) {
		if (is_successed) {
			ResumeThread(main_thread_handle);
		}
		CloseHandle(main_thread_handle);
	}
	if (process_handle) {
		if (!is_successed) {
			TerminateProcess(process_handle, 0xDEAD);
		}
		CloseHandle(process_handle);
	}
}

HANDLE Injector::GetProcessHandle() {
	return process_handle;
}

#ifdef _WIN64
bool Injector::Run(std::wstring wCmdLine) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);

	std::wstring wDir = target_path;
	size_t pos_last_backslash = wDir.rfind(L'\\');
	if (pos_last_backslash != std::wstring::npos) {
		wDir.erase(wDir.begin() + pos_last_backslash + 1, wDir.end());
		if (wCmdLine.length()) {
			if (!CreateProcessW(target_path.c_str(), (LPWSTR)wCmdLine.c_str(), 0, 0, FALSE, CREATE_SUSPENDED, 0, wDir.c_str(), &si, &pi)) {
				return false;
			}
		}
		else {
			if (!CreateProcessW(target_path.c_str(), 0, 0, 0, FALSE, CREATE_SUSPENDED, 0, wDir.c_str(), &si, &pi)) {
				return false;
			}
		}
	}
	else {
		if (wCmdLine.length()) {
			if (!CreateProcessW(target_path.c_str(), (LPWSTR)wCmdLine.c_str(), 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi)) {
				return false;
			}
		}
		else {
			if (!CreateProcessW(target_path.c_str(), 0, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi)) {
				return false;
			}
		}
	}

	process_handle = pi.hProcess;
	main_thread_handle = pi.hThread;

	// Process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
	if (!hProcess) {
		return false;
	}

	CloseHandle(process_handle);
	process_handle = hProcess;

	// Thread
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pi.dwThreadId);
	if (!hThread) {
		return false;
	}

	CloseHandle(main_thread_handle);
	main_thread_handle = hThread;

	// RIP
	CONTEXT ct;
	memset(&ct, 0, sizeof(ct));
	ct.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(main_thread_handle, &ct)) {
		return false;
	}

	void* vCode = VirtualAllocEx(process_handle, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!vCode) {
		return false;
	}

#pragma pack(push, 1)
	typedef struct {
		BYTE bCode[0x50];
		ULONG_PTR uLoadLibraryW;
		ULONG_PTR uEntryPoint;
		WCHAR wPath[MAX_PATH];
	} Loader64;
#pragma pack(pop)

	BYTE bLoader[sizeof(Loader64)] = { 0x48, 0x83, 0xEC, 0x30, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x0D, 0x3E, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x28, 0x00, 0x00, 0x00, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58, 0x48, 0x83, 0xC4, 0x30, 0xFF, 0x25, 0x0F, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
	((Loader64*)(&bLoader[0]))->uLoadLibraryW = (ULONG_PTR)LoadLibraryW;
	((Loader64*)(&bLoader[0]))->uEntryPoint = (ULONG_PTR)ct.Rip;
	memcpy_s(((Loader64*)(&bLoader[0]))->wPath, dll_path.length() * sizeof(wchar_t), dll_path.c_str(), dll_path.length() * sizeof(wchar_t));

	SIZE_T bw;
	if (!WriteProcessMemory(process_handle, vCode, bLoader, sizeof(bLoader), &bw)) {
		return false;
	}

	CONTEXT ctInject = ct;
	ctInject.Rip = (ULONG_PTR)vCode;
	if (!SetThreadContext(main_thread_handle, &ctInject)) {
		return false;
	}

	is_successed = true;
	return true;
}

bool Injector::Inject() {
	if (target_pi.dwProcessId == 0) {
		return false;
	}

	// Process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pi.dwProcessId);
	if (!hProcess) {
		return false;
	}
	process_handle = hProcess;

	// Thread
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, target_pi.dwThreadId);
	if (!hThread) {
		return false;
	}
	main_thread_handle = hThread;

	// RIP
	CONTEXT ct;
	memset(&ct, 0, sizeof(ct));
	ct.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(main_thread_handle, &ct)) {
		return false;
	}

	void* vCode = VirtualAllocEx(process_handle, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!vCode) {
		return false;
	}

#pragma pack(push, 1)
	typedef struct {
		BYTE bCode[0x50];
		ULONG_PTR uLoadLibraryW;
		ULONG_PTR uEntryPoint;
		WCHAR wPath[MAX_PATH];
	} Loader64;
#pragma pack(pop)

	BYTE bLoader[sizeof(Loader64)] = { 0x48, 0x83, 0xEC, 0x30, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x0D, 0x3E, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x28, 0x00, 0x00, 0x00, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58, 0x48, 0x83, 0xC4, 0x30, 0xFF, 0x25, 0x0F, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
	((Loader64*)(&bLoader[0]))->uLoadLibraryW = (ULONG_PTR)LoadLibraryW;
	((Loader64*)(&bLoader[0]))->uEntryPoint = (ULONG_PTR)ct.Rip;
	memcpy_s(((Loader64*)(&bLoader[0]))->wPath, dll_path.length() * sizeof(wchar_t), dll_path.c_str(), dll_path.length() * sizeof(wchar_t));

	SIZE_T bw;
	if (!WriteProcessMemory(process_handle, vCode, bLoader, sizeof(bLoader), &bw)) {
		return false;
	}

	CONTEXT ctInject = ct;
	ctInject.Rip = (ULONG_PTR)vCode;
	if (!SetThreadContext(main_thread_handle, &ctInject)) {
		return false;
	}

	is_successed = true;
	return true;
}

#else
bool Injector::Run(std::wstring wCmdLine) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);

	std::wstring wDir = target_path;
	size_t pos_last_backslash = wDir.rfind(L'\\');
	if (pos_last_backslash != std::wstring::npos) {
		wDir.erase(wDir.begin() + pos_last_backslash + 1, wDir.end());
		if (wCmdLine.length()) {
			if (!CreateProcessW(target_path.c_str(), (LPWSTR)wCmdLine.c_str(), 0, 0, FALSE, CREATE_SUSPENDED, 0, wDir.c_str(), &si, &pi)) {
				return false;
			}
		}
		else {
			if (!CreateProcessW(target_path.c_str(), 0, 0, 0, FALSE, CREATE_SUSPENDED, 0, wDir.c_str(), &si, &pi)) {
				return false;
			}
		}
	}
	else {
		if (wCmdLine.length()) {
			if (!CreateProcessW(target_path.c_str(), (LPWSTR)wCmdLine.c_str(), 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi)) {
				return false;
			}
		}
		else {
			if (!CreateProcessW(target_path.c_str(), 0, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi)) {
				return false;
			}
		}
	}

	process_handle = pi.hProcess;
	main_thread_handle = pi.hThread;

	// Process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
	if (!hProcess) {
		return false;
	}

	CloseHandle(process_handle);
	process_handle = hProcess;

	// Thread
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pi.dwThreadId);
	if (!hThread) {
		return false;
	}

	CloseHandle(main_thread_handle);
	main_thread_handle = hThread;

	// EIP
	CONTEXT ct;
	memset(&ct, 0, sizeof(ct));
	ct.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(main_thread_handle, &ct)) {
		return false;
	}

	void* vPath = VirtualAllocEx(process_handle, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
	if (!vPath) {
		return false;
	}

	SIZE_T bw;
	if (!WriteProcessMemory(process_handle, vPath, dll_path.c_str(), (wcslen(dll_path.c_str()) + 1) * sizeof(wchar_t), &bw)) {
		return false;
	}

	void* vCode = VirtualAllocEx(process_handle, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!vCode) {
		return false;
	}

	BYTE bLoader[] = { 0x50, 0x53, 0x68, 0xAB, 0xAB, 0xAB, 0xAB, 0xE8, 0x35, 0x02, 0x7C, 0x20, 0x5B, 0x58, 0xE9, 0x2E, 0x02, 0x7C, 0x20 };
	*(DWORD*)&bLoader[0x02 + 0x01] = (DWORD)vPath;
	*(DWORD*)&bLoader[0x07 + 0x01] = (DWORD)LoadLibraryW - ((DWORD)vCode + 0x07) - 0x05;
	*(DWORD*)&bLoader[0x0E + 0x01] = (DWORD)ct.Eip - ((DWORD)vCode + 0x0E) - 0x05;
	if (!WriteProcessMemory(process_handle, vCode, bLoader, sizeof(bLoader), &bw)) {
		return false;
	}

	CONTEXT ctInject = ct;
	ctInject.Eip = (DWORD)vCode;
	if (!SetThreadContext(main_thread_handle, &ctInject)) {
		return false;
	}

	is_successed = true;
	return true;
}
#endif