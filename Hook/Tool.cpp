#include "Tool.h"

std::wstring BYTEtoString(BYTE b) {
	std::wstring wb;
	WCHAR high = (b >> 4) & 0x0F;
	WCHAR low = b & 0x0F;

	high += (high <= 0x09) ? 0x30 : 0x37;
	low += (low <= 0x09) ? 0x30 : 0x37;

	wb.push_back(high);
	wb.push_back(low);

	return wb;
}

#ifdef _WIN64
std::wstring QWORDtoString(ULONG_PTR u, bool slim) {
	std::wstring wdw;

	wdw += BYTEtoString((u >> 56) & 0xFF);
	wdw += BYTEtoString((u >> 48) & 0xFF);
	wdw += BYTEtoString((u >> 40) & 0xFF);
	wdw += BYTEtoString((u >> 32) & 0xFF);
	wdw += BYTEtoString((u >> 24) & 0xFF);
	wdw += BYTEtoString((u >> 16) & 0xFF);
	wdw += BYTEtoString((u >> 8) & 0xFF);
	wdw += BYTEtoString(u & 0xFF);

	for (size_t i = 0; wdw.length(); i++) {
		if (0 < i && wdw.at(i) != L'0') {
			wdw.erase(wdw.begin(), wdw.begin() + i);
			break;
		}
	}

	return wdw;
}
#else
std::wstring DWORDtoString(DWORD dw) {
	std::wstring wdw;

	wdw += BYTEtoString((dw >> 24) & 0xFF);
	wdw += BYTEtoString((dw >> 16) & 0xFF);
	wdw += BYTEtoString((dw >> 8) & 0xFF);
	wdw += BYTEtoString(dw & 0xFF);

	return wdw;
}
#endif