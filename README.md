# TMSLauncher
Taiwai Maplestory old version launcher

## Feature
- Fix domain resolve error
- Fix window mode error
- Skip Play Window
- Remove Anti-Cheat(NGS/HS/X3)
- Remove CRC
- Customize game window title
- Multiple game windows

## Test version
The supported version range is TMS113-TMS194  
Please tell me if you find any errors during login to these versions
### Anti-Cheat
- Versions in which HS were removed: 113-183
- Versions in which BC counldn't be removed: 160-165
- Versions in which X3 were removed: 189/192/194
### CRC
- Versions in which CWvsApp::Run CRC were removed: 113-159
- Versions in which CWvsApp::Run CRC counldn't be removed: 160-180
- Versions in which CWvsContext::OnEnterField CRC was removed: 183

## How to use
1. Put Launcher.exe and Hook.dll into MapleStory directory
2. Run Launcher.exe to connect the local game server

## Other
- Change server ip in Launcher.cpp
- Change game window title in Hook.cpp

## Thanks
- [Tools](https://github.com/Riremito/tools) shared by Riremito
- [RemoveAntiCheat_EasyVer](https://github.com/rage123450/EmuClient/blob/develop/EmuMain/EmuMain.cpp) shared by rage123450