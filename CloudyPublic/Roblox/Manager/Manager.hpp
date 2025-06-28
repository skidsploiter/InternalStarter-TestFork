#pragma once
#include <Windows.h>

struct lua_State;

static class Instance {
private:

public:
	static uintptr_t GetDataModel();
	static uintptr_t GetScriptContext(uintptr_t DataModel);
	static uintptr_t GetLuaState(uintptr_t ScriptContext);
	static uintptr_t GetLuaStateUndetected(uintptr_t DataModel);

	static lua_State* CreateThread(uintptr_t LuaState);
};