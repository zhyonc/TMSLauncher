#include "CRC.h"
#include "AobList.h"
#include <windows.h>

bool TMS192_2_RemoveCRC_OnEnterField(Rosemary& r) {

	ULONG_PTR uOnEnterField_Enter_VM = r.Scan(AOB_Scan_TMS192_2_OnEnterField_Enter);
	//+0x91
	ULONG_PTR uOnEnterField_Leave_VM = r.Scan(AOB_Scan_TMS192_2_OnEnterField_Leave);

	if (!uOnEnterField_Enter_VM || !uOnEnterField_Leave_VM) {
		return false;
	}

	r.JMP(uOnEnterField_Enter_VM, uOnEnterField_Leave_VM);
	return true;
}


bool RemoveCRC(Rosemary& r) {
	int check = 0;

	if (TMS192_2_RemoveCRC_OnEnterField(r)) {
		check++;
	}

	return check > 0;
}