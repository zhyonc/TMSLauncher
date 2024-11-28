#include "Play.h"
#include "AobList.h"
#include "Tool.h"

int GetClientVersion(Rosemary& r) {
	// Each version has slightly different assignment instructions
	// CPatchException::CPatchException(68 04 01 00 00 FF ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D)
	return 0;
}

void FixPlay(Rosemary& r) {
	// TMS old default DNS (not available cause crash)
	ULONG_PTR res = r.StringPatch("tw.login.maplestory.gamania.com", "127.0.0.1");
	SCANRES(res);
}

void FixWindowMode(Rosemary& r) {
	// Window Mode is needed to run old client with recent displays
	// or change display settings 59.9 fps to 60.1 fps, 60.1 fps may allow to use full screen mode
	ULONG_PTR Call = r.Scan(AOB_Scan_Window_Mode);
	if (Call == 0) {
		return;
	}
	ULONG_PTR Window_Mode = Call + 0x03;
	r.WriteByte(Window_Mode, 0x00);
}