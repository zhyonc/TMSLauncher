#pragma once
#include <string>

// HS
const std::wstring AOB_Scan_HackShield = L"E8 ?? ?? ?? ?? 85 C0 74 0A E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 00 0F";
const std::wstring AOB_Scan_HS_Key_Crypt = L"E8 ?? ?? ?? ?? EB 05 E8 ?? ?? ?? ?? 66";
const std::wstring AOB_Scan_TMS157_HS_Enter_Charcter_Page = L"83 ?? ?? ?? ?? ?? 00 74 45 83 ?? ?? 00 A1 ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 8D ?? EC 68 ?? ?? ?? ?? 50 C6 ?? ?? 02 E8";
// X3
const std::wstring AOB_Scan_Xigncode3 = L"E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 7D 08 00 0F ?? ?? ?? ?? ?? 6A 00 68 00 00 00 80 6A 02 6A";
// CRC
const std::wstring AOB_Scan_TMS192_2_OnEnterField_Enter = L"E9 ?? ?? ?? ?? 50 EB 55 2C 8A 4A 9C AF 79 54 A0";
const std::wstring AOB_Scan_TMS192_2_OnEnterField_Leave = L"8B ?? ?? ?? ?? ?? 81 ?? EC 68 00 00 E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 8B";
// Code
const std::wstring AOB_Patch_Ret = L"31 C0 C3"; // xor eax,eax ret
