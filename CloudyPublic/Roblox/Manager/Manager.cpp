#include "Manager.hpp"
#include <Update/Offsets/Offsets.hpp>
#include <Luau/Compiler.h>
#include <Luau/BytecodeBuilder.h>
#include <Luau/BytecodeUtils.h>
#include <Luau/Bytecode.h>

#include <lapi.h>
#include <lstate.h>
#include <lualib.h>



uintptr_t Instance::GetDataModel() {
	uintptr_t FakeDataModel = *(uintptr_t*)Offsets::DataModel::FakeDataModelPointer;
	uintptr_t DataModel = *(uintptr_t*)(FakeDataModel + Offsets::DataModel::FakeDataModelToReal);

	uintptr_t NamePtr = *(uintptr_t*)(DataModel + Offsets::Properties::Name);
	std::string DataModelName = *(std::string*)NamePtr;

	if (DataModelName == "LuaApp") {
		return 0x0;
	}

	return DataModel;
}

uintptr_t Instance::GetScriptContext(uintptr_t DataModel) {
	uintptr_t ChildrenList = *(uintptr_t*)(DataModel + Offsets::Properties::Children);
	uintptr_t Children = *(uintptr_t*)(ChildrenList);

	uintptr_t ScriptContext = *(uintptr_t*)(Children + Offsets::ScriptContext::ScriptContext);

	return ScriptContext;
}

uintptr_t Instance::GetLuaState(uintptr_t ScriptContext) {
	uint64_t a2 = 0;
	uint64_t a3 = 0;

	return RBX::GetLuaState(ScriptContext, &a2, &a3);
}

uintptr_t Instance::GetLuaStateUndetected(uintptr_t ScriptContext) {
		uintptr_t EncryptedState = ScriptContext +  Offsets::LuaState::GlobalStatePointer + Offsets::LuaState::GlobalStateStart + Offsets::LuaState::DecryptState;

		uint32_t low = *reinterpret_cast<uint32_t*>(EncryptedState) - (uint32_t)EncryptedState;
		uint32_t high = *reinterpret_cast<uint32_t*>(EncryptedState + 0x4) - (uint32_t)EncryptedState;

		uintptr_t luaState = (static_cast<uint64_t>(high) << 32) | low;

		return luaState;
}

lua_State* Instance::CreateThread(uintptr_t luaState) {
	lua_State* ExploitThread = lua_newthread((lua_State*)luaState);
	luaL_sandboxthread(ExploitThread);
	return ExploitThread;
}