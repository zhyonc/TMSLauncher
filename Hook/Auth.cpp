#include "Auth.h"
#include "AobList.h"
#include "Tool.h"
#include "Share/FunctionHookList.h"

#include<intrin.h>
#pragma intrinsic(_ReturnAddress)

bool RemoveAntiCheat(Rosemary& r) {
	ULONG_PTR Call = 0;
	size_t length = AOB_Scan_CSecurityClient_IsInstantiated_Calls.size();
	size_t index;
	for (index = 0; index < length; index++)
	{
		Call = r.Scan(AOB_Scan_CSecurityClient_IsInstantiated_Calls[index]);
		if (Call > 0) {
			break;
		}
	}
	if (Call == 0) {
		DEBUG(L"CSecurityClientIsInstantiated Calls Not Found");
		return false;
	}
	if (index < 4) {
		// TMS113-TMS183 is HS Version
		RemoveHSKey(r);
	}
	if (index == 0) {
		// TMS113-TMS121 easy HS
		return r.WriteByte(Call, 0xEB);
	}
	if (index == 1) {
		// TMS145 can't find TSingleton<CSecurityClient>::IsInstantiated in CWvsApp::ZtlExceptionHandler
		ULONG_PTR CSecurityClientIsInstantiated = Call + 0x08;
		return r.WriteBytes(CSecurityClientIsInstantiated, AOB_Patch_Ret);
	}
	if (index < 4) {
		// TMS122-TMS192
		// Call TSingleton<CSecurityClient>::IsInstantiated in CWvsApp::ZtlExceptionHandler(68 00 00 00 80 6A 02)
		ULONG_PTR CSecurityClientIsInstantiated = Call + 0x05 + *(signed long int*)(Call + 0x01);
		return r.WriteBytes(CSecurityClientIsInstantiated, AOB_Patch_Ret);
	}
	if (index == 5) {
		// TMS194 can't find TSingleton<CSecurityClient>::IsInstantiated in CWvsApp::ZtlExceptionHandler
		// Call TSingleton<CSecurityClient>::GetInstance in CSecurityClient::EncodeMemoryCheckResult
		ULONG_PTR CSecurityClientIsInstantiated = Call + 0x05 + *(signed long int*)(Call + 0x01) + 0x06;
		return r.WriteBytes(CSecurityClientIsInstantiated, AOB_Patch_Ret);
	}
	DEBUG(L"Unkown index in RemoveAntiCheat");
	return false;
}

void RemoveHSKey(Rosemary& r) {
	// TMS113-TMS183
	ULONG_PTR uKeyCryptCall = r.Scan(AOB_Scan_HS_Key_Crypt);
	if (uKeyCryptCall == 0) {
		DEBUG(L"uKeyCryptCall Not Found");
		return;
	}
	ULONG_PTR uStartKeyCrypt = uKeyCryptCall + 0x05 + *(signed long int*)(uKeyCryptCall + 0x01);
	ULONG_PTR uStopKeyCrypt = uKeyCryptCall + 0x0C + *(signed long int*)(uKeyCryptCall + 0x08);
	r.WriteBytes(uStartKeyCrypt, AOB_Patch_Ret);
	r.WriteBytes(uStopKeyCrypt, AOB_Patch_Ret);
}

void HSThing(Rosemary& r) {
	// TMS157.2 HS things (when enter character select page)
	ULONG_PTR uHS_things = r.Scan(AOB_Scan_HS_Enter_Charcter_Page_TMS157);
	if (uHS_things == 0) {
		DEBUG(L"uHS_things Not Found");
		return;
	}
	r.JMP(uHS_things, uHS_things + 0x4E); //r.JMP(0x60ED4F, 0x60ED9D);
}

// TODO
// See https://forum.ragezone.com/threads/remove-ngs-xc-available-any-regions-2015-~-current-version.1231028/
void(__thiscall* SendWvsSetUpStep)(int, int);
void __fastcall SendWvsSetUpStep_Hook(int nWvsSetUpStep, int nNGSRet) {
	// Use SCANRES get step 12 retaddr and assign it to step 1 retaddr then rebuild
	if ((int)nWvsSetUpStep == 12) {
		ULONG_PTR retaddr = (ULONG_PTR)_ReturnAddress();
		SCANRES(retaddr);
	}
	else if ((int)nWvsSetUpStep == 1) {
		// *(ULONG_PTR*)_AddressOfReturnAddress() = retaddr; // << Step 12's retaddr(it's inside VM block)
	}
	SendWvsSetUpStep(nWvsSetUpStep, nNGSRet);
}

void HookSendWvsSetUpStep(Rosemary& r) {
	ULONG_PTR Call = r.Scan(AOB_Scan_SendWvsSetupStep);
	if (Call == 0) {
		return;
	}
	FunctionHookList::Add(SendWvsSetUpStep_Hook, &SendWvsSetUpStep, Call);
}