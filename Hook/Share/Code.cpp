#include"Code.h"

Code::Code(std::wstring wCode) {
	init = CreateCode(wCode);
}

bool Code::CreateCode(std::wstring wCode) {
	if (wCode.length() < 2) {
		return false;
	}

	std::wstring Code;

	for (size_t i = 0; i < wCode.length(); i++) {
		if (wCode[i] == L' ') {
			continue;
		}
		if (L'0' <= wCode[i] && wCode[i] <= L'9') {
			Code.push_back(wCode[i]);
			continue;
		}
		if (L'A' <= wCode[i] && wCode[i] <= L'F') {
			Code.push_back(wCode[i]);
			continue;
		}
		if (L'a' <= wCode[i] && wCode[i] <= L'f') {
			Code.push_back((unsigned short)wCode[i] - 0x20);
			continue;
		}
		return false;
	}

	if (Code.length() % 2) {
		return false;
	}

	for (size_t i = 0; i < Code.length(); i += 2) {
		unsigned char t = 0x00;
		if (L'0' <= Code[i] && Code[i] <= L'9') {
			t |= ((unsigned char)Code[i] - 0x30) << 4;
		}
		else if (L'A' <= Code[i] && Code[i] <= L'F') {
			t |= ((unsigned char)Code[i] - 0x37) << 4;
		}
		if (L'0' <= Code[i + 1] && Code[i + 1] <= L'9') {
			t |= ((unsigned char)Code[i + 1] - 0x30);
		}
		else if (L'A' <= Code[i + 1] && Code[i + 1] <= L'F') {
			t |= ((unsigned char)Code[i + 1] - 0x37);
		}

		code.push_back(t);
	}

	return true;
}

bool Code::Write(ULONG_PTR uAddress) {
	if (!init) {
		return false;
	}

	if (!code.size()) {
		return false;
	}

	DWORD old = 0;
	if (!VirtualProtect((void*)uAddress, code.size(), PAGE_EXECUTE_READWRITE, &old)) {
		return false;
	}

	for (size_t i = 0; i < code.size(); i++) {
		((BYTE*)uAddress)[i] = code[i];
	}

	VirtualProtect((void*)uAddress, code.size(), old, &old);
	return true;
}