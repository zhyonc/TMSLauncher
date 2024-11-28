#pragma once
#include <vector>
#include <string>


class AobScan {
private:
	bool init;
	std::vector<unsigned char> array_of_bytes;
	std::vector<unsigned char> mask;

	bool CreateAob(std::wstring wAob);

public:
	AobScan(std::wstring wAob);
	bool Compare(unsigned __int64 uAddress);
	size_t size();
};