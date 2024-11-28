#pragma once
#include "../Share/Rosemary.h"

// Remove AntiCheat
bool RemoveAntiCheat(Rosemary& r);
// For HS Version
void RemoveHSKey(Rosemary& r);
// Not used
void HSThing(Rosemary& r);
// For NGS after TMS222
void HookSendWvsSetUpStep(Rosemary& r);