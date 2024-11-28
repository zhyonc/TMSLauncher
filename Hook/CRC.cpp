#include "CRC.h"
#include "AobList.h"
#include "Tool.h"
#include "Share/FunctionHookList.h"

#include<intrin.h>
#pragma intrinsic(_ReturnAddress)

ULONG_PTR uRenderFrame = 0;
ULONG_PTR uRunderFrameJmpVM = 0;
void(__thiscall* IWzGr2D_RenderFrame)(void* ecx);
void __fastcall IWzGr2D_RenderFrame_Hook(void* ecx, void* edx) {
	// call IWzGr2D::RenderFrame
	if ((((BYTE*)_ReturnAddress())[-0x05] == 0xE8)) {
		ULONG_PTR Call = (ULONG_PTR) & ((BYTE*)_ReturnAddress())[-0x05] + *(signed long*)&((BYTE*)_ReturnAddress())[-0x04] + 0x05;

		if (Call == uRenderFrame) {
			// Prevent the client from getting stuck when selecting character
			return IWzGr2D_RenderFrame(ecx);
		}
		// MSEA v102 jmp vmed, vmed: jmp RenderFrame
		// 00B975B5 - call 004172E2 // RederFrame
		// 004172E2 - jmp 0083C5F0 // wtf
		if (((BYTE*)Call)[0x00] == 0xE9) {
			Call = Call + *(signed long*)&((BYTE*)Call)[0x01] + 0x05;
			if (Call == uRenderFrame) {
				// Prevent the client crash when entering field
				return IWzGr2D_RenderFrame(ecx);
			}
		}
	}
	
	// IWzGr2D::RenderFrame ret->CWvsApp::Run
	*(ULONG_PTR*)_AddressOfReturnAddress() = uRunderFrameJmpVM;
	return IWzGr2D_RenderFrame(ecx);
}

bool RemoveRenderFrameCheck(Rosemary& r) {
	uRenderFrame = r.Scan(AOB_Scan_IWzGr2D_RenderFrame); // IWzGr2D::RenderFrame
	if (uRenderFrame == 0) {
		return false;
	}
	
	uRunderFrameJmpVM = r.Scan(AOB_Scan_IWzGr2D_RenderFrame_JMP_CWvsApp_Run); // CWvsApp::Run
	if (uRunderFrameJmpVM >= 0x00C045E0) {
		// TMS160.1 uRunderFrameJmpVM is 0x00C045E0
		// This hook make client crash begin from TMS160
		return false;
	}
	return FunctionHookList::Add(IWzGr2D_RenderFrame_Hook, &IWzGr2D_RenderFrame, uRenderFrame);
}

bool RemoveCWvsContextOnEnterFieldCheck(Rosemary& r) {
	ULONG_PTR Call = r.Scan(AOB_Scan_CWvsContext_OnEnterField);
	if (Call == 0) {
		return false;
	}
	// Enter_VM AOB start at E9 8C 00 00 00
	ULONG_PTR uOnEnterField_Enter_VM = Call + 0x10;
	// Leave_VM AOB start at 8B 8D ?? FE FF FF 
	ULONG_PTR uOnEnterField_Leave_VM = uOnEnterField_Enter_VM + 0x91; // <-Enter_VM+0x91

	if (!uOnEnterField_Enter_VM || !uOnEnterField_Leave_VM) {
		return false;
	}

	return r.JMP(uOnEnterField_Enter_VM, uOnEnterField_Leave_VM);
}

bool RemoveCRC(Rosemary& r) {
	int check = 0;
	if (RemoveRenderFrameCheck(r)) {
		check++;
	}
	if (RemoveCWvsContextOnEnterFieldCheck(r)) {
		check++;
	}
	return check > 0;
}