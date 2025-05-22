#pragma once
#include <string>

namespace Config {
	// Tool
	const bool IsDebugMode = true;
	// Socket
	// If the server is not a distributed architecture, set channel server addr same with login server addr
	const std::string ChannelServerAddr = "127.0.0.1";
	const std::string LoginServerAddr = "127.0.0.1";
	const unsigned short LoginServerPort = 8484;
	const bool IsSendConnectKey = false;
	const std::string ConnectKey = "secret";
	const bool IsRecvXOR = false;
	const unsigned char RecvXOR = 0xC;
	// Screen
	const std::string WindowTitle = "goms";
	const bool IsMultipleClient = true;
	// ImgFile
	const bool IsImgFile = false;
}