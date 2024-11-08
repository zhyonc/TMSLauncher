#pragma once
#include <vector>
#include <string>
#include <windows.h>

class Code {
private:
	bool init;
	std::vector<unsigned char> code;

	bool CreateCode(std::wstring wCode);

public:
	Code(std::wstring wCode);
	bool Write(ULONG_PTR uAddress);
};