#pragma once
#include "Share/FunctionHookList.h"
#include <string>

// Remove NGS/HS/X3
void HookStartupInfoA();
// Skip Play Window and Customize game window title
void HookCreateWindowExA();
// Multiple game windows
void HookCreateMutexA();
// Not used
void UnHook();