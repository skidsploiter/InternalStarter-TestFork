#include "TaskScheduler/TaskScheduler.hpp"
#include "Roblox/Manager/Manager.hpp"
#include "Roblox/Utils/Util.hpp"
#include "Update/Offsets/Offsets.hpp"
#include <thread>
#include <sstream>
#include "Roblox/Execution/Execution.hpp"
#include "Communication/NamedPipe/NamedPipe.hpp"


using namespace Globals;

ExecutionMode GlobalMode = LUAU_LOAD; // <-- set mode here LUAU_LOAD or LUAVM_LOAD supported.

void mainthread() {
	Utils::PatchDetection((void*)RBX::Print, sizeof(RBX::Print));
	std::thread(Utils::TpHandler).detach();
	while (!ExploitThread && !DataModel) {
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	Communication::NamedPipe::InitializeNamePipe(GlobalMode);
	

	
	while (true) {

	}
}

BOOL APIENTRY DllMain(HMODULE h, DWORD ul, LPVOID lp) {

	std::thread(mainthread).detach();
	while (true);
	return TRUE;
}
