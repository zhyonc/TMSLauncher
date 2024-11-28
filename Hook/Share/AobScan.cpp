#include "AobScan.h"

AobScan::AobScan(std::wstring wAob) {
	init = CreateAob(wAob);
}

bool AobScan::CreateAob(std::wstring wAob) {
	if (wAob.length() < 2) {
		return false;
	}

	std::wstring Aob;

	for (size_t i = 0; i < wAob.length(); i++) {
		if (wAob[i] == L' ') {
			continue;
		}
		if (L'0' <= wAob[i] && wAob[i] <= L'9') {
			Aob.push_back(wAob[i]);
			continue;
		}
		if (L'A' <= wAob[i] && wAob[i] <= L'F') {
			Aob.push_back(wAob[i]);
			continue;
		}
		if (L'a' <= wAob[i] && wAob[i] <= L'f') {
			Aob.push_back((unsigned short)wAob[i] - 0x20);
			continue;
		}
		if (wAob[i] == L'?' || wAob[i] == L'*') {
			Aob.push_back(L'?');
			continue;
		}
		return false;
	}

	if (Aob.length() % 2) {
		return false;
	}

	for (size_t i = 0; i < Aob.length(); i += 2) {
		unsigned char t = 0x00;
		int m = 0;
		if (Aob[i] == L'?') {
			m |= 1;
		}
		if (L'0' <= Aob[i] && Aob[i] <= L'9') {
			t |= ((unsigned char)Aob[i] - 0x30) << 4;
		}
		else if (L'A' <= Aob[i] && Aob[i] <= L'F') {
			t |= ((unsigned char)Aob[i] - 0x37) << 4;
		}
		if (Aob[i + 1] == L'?') {
			m |= 2;
		}
		if (L'0' <= Aob[i + 1] && Aob[i + 1] <= L'9') {
			t |= ((unsigned char)Aob[i + 1] - 0x30);
		}
		else if (L'A' <= Aob[i + 1] && Aob[i + 1] <= L'F') {
			t |= ((unsigned char)Aob[i + 1] - 0x37);
		}

		array_of_bytes.push_back(t);
		mask.push_back(m);
	}

	return true;
}


bool AobScan::Compare(unsigned __int64 uAddress) {
	if (!init) {
		return false;
	}

	try {
		for (size_t i = 0; i < array_of_bytes.size(); i++) {
			// ignore
			if (mask[i] == 3) {
				continue;
			}
			// compare
			if (mask[i] == 0 && ((unsigned char*)uAddress)[i] == array_of_bytes[i]) {
				continue;
			}
			// ignore high
			if (mask[i] == 1 && (((unsigned char*)uAddress)[i] & 0x0F) == (array_of_bytes[i] & 0x0F)) {
				continue;
			}
			// ignore low
			if (mask[i] == 2 && (((unsigned char*)uAddress)[i] & 0xF0) == (array_of_bytes[i] & 0xF0)) {
				continue;
			}

			return false;
		}
	}
	catch (...) {
		return false;
	}

	return true;
}

size_t AobScan::size() {
	return array_of_bytes.size();
}