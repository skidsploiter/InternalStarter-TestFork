#pragma once
#include <Windows.h>
struct lua_State;
struct Proto;

static class TaskScheduler {
private:

public:
	static void SetFPS(int fpsvalue);
	static void SetThreadCapabilities(lua_State* l, int identity, uintptr_t capabilities);
	static void SetProtoCapabilities(Proto* proto);

	// unused, but useful
	static void CfgBypass(uintptr_t address);
};