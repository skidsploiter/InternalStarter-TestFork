#include "Execution.hpp"
#include <Luau/Compiler.h>
#include <Luau/BytecodeBuilder.h>
#include <Luau/BytecodeUtils.h>
#include <Luau/Bytecode.h>

#include <lapi.h>
#include <lstate.h>
#include <lualib.h>
#include <Update/Offsets/Offsets.hpp>
#include <TaskScheduler/TaskScheduler.hpp>
#include "Roblox/Manager/Manager.hpp"
#include <Roblox/Utils/Util.hpp>

#include <Dependencies/zstd/include/zstd/xxhash.h>
#include <Dependencies/zstd/include/zstd/zstd.h>
using namespace Globals;

class LuauLoadByteCodeEncoderClass : public Luau::BytecodeEncoder {
	void encode(uint32_t* data, size_t count) override {
		for (auto i = 0; i < count;) {
			uint8_t op = LUAU_INSN_OP(data[i]);
			const auto oplen = Luau::getOpLength((LuauOpcode)op);
			BYTE* OpCodeLookUpTable = reinterpret_cast<BYTE*>(Offsets::Opcodes::Opcodelookuptable);
			uint8_t new_op = op * 227;
			new_op = OpCodeLookUpTable[new_op];
			data[i] = (new_op) | (data[i] & ~0xff);
			i += oplen;
		}
	}
};

class LuaVMLoadByteCodeEncoderClass : public Luau::BytecodeEncoder {
	inline void encode(uint32_t* ptr, size_t len) override {
		size_t idx = 0;
		while (idx < len) {
			auto& inst = *(uint8_t*)(ptr + idx);
			auto step = Luau::getOpLength(LuauOpcode(inst));
			inst *= 227;
			idx += step;
		}
	}
};



LuauLoadByteCodeEncoderClass LuauLoadEncoder;
LuaVMLoadByteCodeEncoderClass LuaVMLoadEncoder;

std::string CloudyExecution::CompileScript(const std::string src, ExecutionMode mode) {

	switch (mode) {
	case LUAU_LOAD: {
		Luau::CompileOptions options;
		options.debugLevel = 1;
		options.optimizationLevel = 1;
		const char* mutableGlobals[] = {
			"Game", "Workspace", "game", "plugin", "script", "shared", "workspace",
			"_G", "_ENV", nullptr
		};
		options.mutableGlobals = mutableGlobals;
		options.vectorLib = "Vector3";
		options.vectorCtor = "new";
		options.vectorType = "Vector3";

		return Luau::compile(src, options, {}, &LuauLoadEncoder);
	}
	case LUAVM_LOAD: {
		auto compiled = Luau::compile(src, { 1, 1, 2 }, { true, true }, &LuaVMLoadEncoder);

		auto rawSize = compiled.size();
		auto compBound = ZSTD_compressBound(rawSize);
		std::vector<char> output(compBound + 8);

		memcpy(output.data(), "RSB1", 4);
		memcpy(output.data() + 4, &rawSize, sizeof(rawSize));

		auto compSize = ZSTD_compress(output.data() + 8, compBound, compiled.data(), rawSize, ZSTD_maxCLevel());
		auto total = compSize + 8;

		auto hash = XXH32(output.data(), total, 42);
		auto* keys = reinterpret_cast<uint8_t*>(&hash);

		for (size_t i = 0; i < total; ++i) {
			output[i] ^= keys[i % 4] + i * 41;
		}

		return std::string(output.data(), total);
	}
	default:
		MessageBoxA(0, 0, 0, 0);
	}
}


void CloudyExecution::LuauLoad(lua_State* l, const std::string& src, const char* container) {
	const int originalTop = lua_gettop(l);
	auto thread = lua_newthread(l);
	lua_pop(l, 1);
	TaskScheduler::SetThreadCapabilities(thread, 8, MAXCAPABILITIES); // --> "CreateInstances" Permission in order to create new "LocalScript"
	auto Source = CompileScript(src + "\nscript = Instance.new('LocalScript');", LUAU_LOAD);
	if (luau_load(thread, container, Source.c_str(), Source.length(), 0) != LUA_OK)
	{
		const char* err = lua_tostring(thread, -1);
		RBX::Print(2, err);
		return;
	}
	Closure* closure = (Closure*)lua_topointer(thread, -1);
	if (closure && closure->l.p)
		TaskScheduler::SetProtoCapabilities(closure->l.p);

	lua_getglobal(l, "task");
	lua_getfield(l, -1, "defer");
	lua_remove(l, -2);
	lua_xmove(thread, l, 1);

	if (lua_pcall(l, 1, 0, 0) != LUA_OK) {
		const char* err = lua_tostring(l, -1);
		if (err) RBX::Print(2, err);
		lua_pop(l, 1);
		return;
	}

	lua_settop(thread, 0);
	lua_settop(l, originalTop);

}

void CloudyExecution::LuaVMLoad(lua_State* l, const std::string& src, const char* container) {
	auto data = CompileScript(src, LUAVM_LOAD);
	lua_settop(l, 0);
	lua_gc(l, LUA_GCSTOP, 0);

	auto thread = lua_newthread(l);
	luaL_sandboxthread(thread);
	if (!thread) {
		lua_gc(l, LUA_GCRESTART, 0);
		return;
	}
	lua_settop(thread, 0);
	// taskdefer
	lua_getglobal(thread, "task");
	lua_getfield(thread, -1, "defer");

	TaskScheduler::SetThreadCapabilities(thread, 8, MAXCAPABILITIES);

	auto res = RBX::LuaVM__Load(thread, &data, container, 0);
	if (res != LUA_OK) {
		std::string err = luaL_checklstring(thread, -1, nullptr);
		lua_pop(thread, 1);
		lua_gc(l, LUA_GCRESTART, 0);
		return;
	}
	auto* func = clvalue(luaA_toobject(thread, -1));
	if (!func) {
		lua_gc(l, LUA_GCRESTART, 0);
		return;
	}

	TaskScheduler::SetProtoCapabilities(func->l.p);

	if (lua_pcall(thread, 1, 0, 0) != LUA_OK) {
		std::string err = luaL_checklstring(thread, -1, nullptr);
		lua_pop(thread, 1);
		lua_gc(l, LUA_GCRESTART, 0);
		return;
	}

	lua_pop(thread, 1);
	lua_gc(l, LUA_GCRESTART, 0);

}



void CloudyExecution::Execute(lua_State* l, std::string src, ExecutionMode mode) {
	if (src.empty()) return;

	switch (mode) {
	case LUAU_LOAD: {
		LuauLoad(l, src, "@Cloudy");
		break;
	}


	case LUAVM_LOAD: {
		LuaVMLoad(l, src, "@Cloudy");
		break;
	}

	default:
		MessageBoxA(nullptr, "No Execution method was provided. Skipping...", "CloudyExecution", 0);


	}
}