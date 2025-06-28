#include "Util.hpp"
#include "../Manager/Manager.hpp"
#include <Update/Offsets/Offsets.hpp>
#include <sstream>
#include <TaskScheduler/TaskScheduler.hpp>
#include <Roblox/Execution/Execution.hpp>
#include "Environment/Environment.hpp"
#include <inttypes.h>

using namespace Globals;

bool Utils::IsAddressValid(uintptr_t address) {
	if (address < 0x10000 || address > 0x7FFFFFFFFFFF) {
		return false;
	}
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) == 0) {
		return false;
	}
	if (mbi.Protect & PAGE_NOACCESS || mbi.State != MEM_COMMIT) {
		return false;
	}
	return true;
}

bool Utils::InitializeClient() {
	DataModel = Instance::GetDataModel();
	uintptr_t ScriptContext = Instance::GetScriptContext(DataModel);
	uintptr_t LuaState = Instance::GetLuaState(ScriptContext);
	ExploitThread = Instance::CreateThread(LuaState);
	TaskScheduler::SetThreadCapabilities(ExploitThread, 8, MAXCAPABILITIES);

	TaskScheduler::SetFPS(120); // --> optional

	// ENVIRONMENT LOADING::
	while (!ExploitThread) {
		Sleep(1000);
	}
	Sleep(1000);
	Environment::Init(ExploitThread);
	return true;
}

void Utils::TpHandler() {

	while (true) {
		uintptr_t cachedDm = Instance::GetDataModel();
		if (cachedDm == 0x0) {
			continue;
		}
		else if (Utils::IsAddressValid(cachedDm)) {
			if (cachedDm != DataModel) {
				DataModel = cachedDm;
				uint64_t PlaceID = *reinterpret_cast<uint64_t*>(DataModel + Offsets::Security::PlaceId);
				std::ostringstream ss;
				ss << "[TPHANDLER] -> New PlaceID: " << PlaceID;
				RBX::Print(1, ss.str().c_str());
				while (!InitializeClient())
					Sleep(100);
				continue;
			}
		}
		else if (!Utils::IsAddressValid(cachedDm)) {
			RBX::Print(3, "Datamodel corrupted");
			continue;
		}
		else {
			RBX::Print(3, "Datamodel returned unexpected data.");
		}
		Sleep(1000);
	}
}


// -- In order for that function to work, you would need the byfron integritycheck bypass. -- //
void Utils::PatchDetection(void* targetFunc, size_t size) {
	DWORD op;
	VirtualProtect(targetFunc, size, PAGE_EXECUTE_READWRITE, &op);

	uint8_t* code = reinterpret_cast<uint8_t*>(targetFunc);
	for (size_t i = 0; i < size; ++i) {
		if (code[i] == 0xCC) {
			code[i] = 0x90;  // int3 to nop
		}
	}

	VirtualProtect(targetFunc, size, op, &op);
}
