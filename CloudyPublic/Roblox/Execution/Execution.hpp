#pragma once
#include <Windows.h>
#include <string>
#include <memory>

struct lua_State;

static enum ExecutionMode {
	LUAU_LOAD,
	LUAVM_LOAD
};


static class CloudyExecution {
private:

public:
	std::string CompileScript(const std::string Src, ExecutionMode mode);
	void Execute(lua_State* thread, std::string luacode, ExecutionMode mode);

	void LuauLoad(lua_State* thread, const std::string& luacode, const char* container);
	void LuaVMLoad(lua_State* thread, const std::string& luacode, const char* container);

};
inline auto Execution = std::make_unique<CloudyExecution>();