#include "Auth.h"
#include "AobList.h"

void ResolveDomain(Rosemary& r) {
	r.StringPatch("tw.login.maplestory.gamania.com", "127.0.0.1");
}

bool RemoveHS(Rosemary& r) {
	// HS
	int check = 0;
	ULONG_PTR Call = r.Scan(AOB_Scan_HackShield);
	if (Call != 0) {
		ULONG_PTR uCSecurityClient__IsInstantiated = Call + 0x05 + *(signed long int*)(Call + 0x01);
		r.Patch(uCSecurityClient__IsInstantiated, AOB_Patch_Ret);
		check++;
	}
	// HS Key
	ULONG_PTR uKeyCryptCall = r.Scan(AOB_Scan_HS_Key_Crypt);
	if (uKeyCryptCall != 0) {
		ULONG_PTR uStartKeyCrypt = uKeyCryptCall + 0x05 + *(signed long int*)(uKeyCryptCall + 0x01);
		ULONG_PTR uStopKeyCrypt = uKeyCryptCall + 0x0C + *(signed long int*)(uKeyCryptCall + 0x08);
		r.Patch(uStartKeyCrypt, AOB_Patch_Ret);
		r.Patch(uStopKeyCrypt, AOB_Patch_Ret);
		check++;
	}
	//TMS157.2 HS things (when enter character select page)
	ULONG_PTR uHS_things = r.Scan(AOB_Scan_TMS157_HS_Enter_Charcter_Page);
	if (uHS_things != 0) {
		r.JMP(uHS_things, uHS_things + 0x4E); //r.JMP(0x60ED4F, 0x60ED9D);
		check++;
	}
	return check > 0;
}

bool RemoveX3(Rosemary& r) {
	ULONG_PTR Call = r.Scan(AOB_Scan_Xigncode3);
	if (Call == 0) {
		return false;
	}
	ULONG_PTR uCSecurityClient__IsInstantiated = Call + 0x05 + *(signed long int*)(Call + 0x01) + 0x06; //TMS192.2 5C9A49
	r.Patch(uCSecurityClient__IsInstantiated, AOB_Patch_Ret);
	return true;
}