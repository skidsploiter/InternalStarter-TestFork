#include "TaskScheduler.hpp"
#include <Luau/Compiler.h>
#include <Luau/BytecodeBuilder.h>
#include <Luau/BytecodeUtils.h>
#include <Luau/Bytecode.h>

#include <lapi.h>
#include <lstate.h>
#include <lualib.h>

uintptr_t MaxCapabilities = ~0ULL;


void TaskScheduler::SetFPS(int fps) {
	*(int*)(Offsets::Instance::TaskSchedulerTargetFps) = fps;
}

void TaskScheduler::SetProtoCapabilities(Proto* proto) {
	proto->userdata = &MaxCapabilities;
	for (int i = 0; i < proto->sizep; i++) {
		SetProtoCapabilities(proto->p[i]);
	}
}

void TaskScheduler::SetThreadCapabilities(lua_State* L, int identity, uintptr_t capabilities) {
	auto ExtraSpace = (uintptr_t)(L->userdata);
	*(uintptr_t*)(ExtraSpace + Offsets::Luau::userdata::ExtraSpace::Identity) = identity;
	*(uintptr_t*)(ExtraSpace + Offsets::Luau::userdata::ExtraSpace::Capabilities) = capabilities;
	std::int64_t Ignore[128];
	RBX::Impersonator(Ignore, &identity, (__int64)((uintptr_t)L->userdata + Offsets::Luau::userdata::ExtraSpace::Capabilities));
}

void TaskScheduler::CfgBypass(uintptr_t address) {
	uintptr_t byteOffset = (address >> 0x13);
	uintptr_t bitOffset = (address >> 0x10) & 7;

	uint8_t* Cache = (uint8_t*)(Offsets::Hyperion::BitMap + byteOffset);

	DWORD oldProtect;
	VirtualProtect(Cache, 1, PAGE_READWRITE, &oldProtect);

	*Cache |= (1 << bitOffset);

	VirtualProtect(Cache, 1, oldProtect, &oldProtect);
}