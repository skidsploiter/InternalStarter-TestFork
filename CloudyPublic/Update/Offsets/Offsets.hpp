#pragma once
#include <Windows.h>
#include <iostream>

struct lua_State;
#define rebase(x) x + (uintptr_t)GetModuleHandleA(nullptr)
#define rebasehyperion(x) x + (uintptr_t)GetModuleHandleA("RobloxPlayerBeta.dll")
#define MAXCAPABILITIES (0x200000000000003FLL | 0xFFFFFFF00LL) | (1ull << 48ull)
/*
updated for version-78712d8739f34cb9
Last Commit: 2025/06/26
by Volxphy
*/

namespace Offsets {
	inline uintptr_t Print = rebase(0x156D240);
	inline uintptr_t KTable = rebase(0x63341B0);
	namespace DataModel {
		inline uintptr_t FakeDataModelPointer = rebase(0x67633D8);
		inline uintptr_t FakeDataModelToReal = 0x1B8;
		inline uintptr_t HeartBeatDataModelInstance = 0x550;
		inline uintptr_t GameLoaded = 0x650;
	}

	namespace Instance {
		inline uintptr_t TaskSchedulerTargetFps = rebase(0x6334134);
		inline uintptr_t RawScheduler = rebase(0x6829508);
		inline uintptr_t Task__Defer = rebase(0xFD9350);
		inline uintptr_t GetCurrentThreadId = rebase(0x3811260);

		namespace FastFlags {
			inline uintptr_t LockViolationInstanceCrash = rebase(0x5FB2898);
		}

		namespace FireClickDetector {
			inline uintptr_t FireMouseClick = rebase(0x1C5E9F0);
			inline uintptr_t FireRightMouseClick = rebase(0x1C5EB90);
			inline uintptr_t FireMouseHoverEnter = rebase(0x1C5FF90);
			inline uintptr_t FireMouseHoverLeave = rebase(0x1C60130);
		}
	}

	namespace Luau {
		namespace VM {
			inline uintptr_t LuaH_DummyNode = rebase(0x46D41F8);
			inline uintptr_t Luau_Execute = rebase(0x268CFD0);
			inline uintptr_t LuaO_NilObject = rebase(0x46D47D8);
			inline uintptr_t LuaD_throw = rebase(0x265A390);
		}

		namespace userdata {
			inline uintptr_t Impersonator = rebase(0x3319D50);


			namespace ExtraSpace {
				inline uintptr_t Identity = 0x30;
				inline uintptr_t Capabilities = 0x48;
			}
		}
	}

	namespace LuaState {
		inline uintptr_t GetLuaState = rebase(0xB49840);
		inline uintptr_t LuaVM__Load = rebase(0xB4DD30);
		inline uintptr_t GlobalStatePointer = 0x140;
		inline uintptr_t GlobalStateStart = 0x188;
		inline uintptr_t DecryptState = 0x88;
	}

	namespace ScriptContext {
		inline uintptr_t ScriptContextStart = 0x1F8;
		inline uintptr_t ScriptContext = 0x3B0;
	}

	namespace Properties {
		inline uintptr_t ClassDescriptor = 0x18;
		inline uintptr_t PropertyDescriptor = 0x3B8;
		inline uintptr_t ClassName = 0x8;
		inline uintptr_t Name = 0x78;
		inline uintptr_t Children = 0x80;
	}

	namespace Scripts {
		inline uintptr_t LocalScriptEmbedded = 0x1B0;
		inline uintptr_t LocalScriptHash = 0x1C0;
		inline uintptr_t ModuleScriptEmbedded = 0x158;
		inline uintptr_t ModuleScriptHash = 0x180;
	}

	namespace Thread {
		inline uintptr_t weak_thread_node = 0x188;
		inline uintptr_t weak_thread_ref = 0x8;
		inline uintptr_t weak_thread_ref_live = 0x20;
		inline uintptr_t weak_thread_ref_live_thread = 0x8;
	}


	namespace Job {
		inline uintptr_t FpsCap = 0x1B0;
		inline uintptr_t JobStart = 0x1D0;
		inline uintptr_t JobName = 0x18;
	}

	namespace Networking {
		inline uintptr_t RakNetBase = 0x218;
	}

	namespace Security {
		inline uintptr_t Require_bypass = 0x6E0;
		inline uintptr_t PlaceId = 0x1A0;
	}

	namespace FireEvents {
		inline uintptr_t FireTouchInterest = rebase(0x1442C20);
		inline uintptr_t FireProximityPrompt = rebase(0x1D28600);
	}

	namespace Functions {
		inline uintptr_t GetProperty = rebase(0xA65200);
		inline uintptr_t PushInstance = rebase(0xE912D0);
		inline uintptr_t RequestCode = rebase(0x913820);
		inline uintptr_t TaskDefer = rebase(0xFD9350);
	}

	namespace Hyperion {
		inline uintptr_t BitMap = rebasehyperion(0x2B6660);
	}

	namespace Yara {
		constexpr uintptr_t YaraBase = 0x2B87EC;
		constexpr uintptr_t SCAN_NEUTRAL = 0x8;
		constexpr uintptr_t BAD_CERTIFICATE = 0x4;
		constexpr uintptr_t SUSPICIOUS = 0xC;
		constexpr uintptr_t LIKELY_MALICIOUS = 0x10;
		constexpr uintptr_t MALICIOUS = 0x14;
	}

	namespace Opcodes {
		inline uintptr_t Opcodelookuptable = rebase(0x55C50B0);
	}

	
	
	constexpr uintptr_t GlobalState = 0x140;
	constexpr uintptr_t EncryptedState = 0x88;
}


namespace RBX {
	using TPrint = void(__cdecl*)(int, const char*, ...);
	inline auto Print = reinterpret_cast<TPrint>(Offsets::Print);

	using TLuaVM__Load = int(__fastcall*)(lua_State*, void*, const char*, int);
	inline auto LuaVM__Load = reinterpret_cast<TLuaVM__Load>(Offsets::LuaState::LuaVM__Load);

	inline auto Impersonator = (void(__fastcall*)(std::int64_t*, std::int32_t*, std::int64_t))Offsets::Luau::userdata::Impersonator;

	using TTask__Defer = int(__fastcall*)(lua_State*);
	inline auto Task__Defer = reinterpret_cast<TTask__Defer>(Offsets::Instance::Task__Defer);

	using TGetLuaState = uintptr_t(__fastcall*)(int64_t, uint64_t*, uint64_t*);
	inline auto GetLuaState = reinterpret_cast<TGetLuaState>(Offsets::LuaState::GetLuaState);

	using TPushInstance = void(__fastcall*)(lua_State* state, void* instance);
	inline auto PushInstance = reinterpret_cast<TPushInstance>(Offsets::Functions::PushInstance);

	using TLuaD_throw = void(__fastcall*)(lua_State*, int);
	inline auto LuaD_throw = reinterpret_cast<TLuaD_throw>(Offsets::Luau::VM::LuaD_throw);

	using TGetProperty = uintptr_t * (__thiscall*)(uintptr_t, uintptr_t*);
	inline auto GetProperty = reinterpret_cast<TGetProperty>(Offsets::Functions::GetProperty);

	using TFireTouchInterest = void(__fastcall*)(uintptr_t, uintptr_t, uintptr_t, bool, bool);
	inline auto FireTouchInterest = reinterpret_cast<TFireTouchInterest>(Offsets::FireEvents::FireTouchInterest);

	using TFireProxmityPrompt = std::uintptr_t(__fastcall*)(std::uintptr_t prompt);
	inline auto FireProximityPrompt = reinterpret_cast<TFireProxmityPrompt>(Offsets::FireEvents::FireProximityPrompt);

	using TRequestCode = uintptr_t(__fastcall*)(uintptr_t protected_string_ref, uintptr_t script);
	inline auto RequestCode = reinterpret_cast<TRequestCode>(Offsets::Functions::RequestCode);

	using TFireMouseClick = void(__fastcall*)(__int64 a1, float a2, __int64 a3);
	inline auto FireMouseClick = reinterpret_cast<TFireMouseClick>(Offsets::Instance::FireClickDetector::FireMouseClick);

	using TFireRightMouseClick = void(__fastcall*)(__int64 a1, float a2, __int64 a3);
	inline auto FireRightMouseClick = reinterpret_cast<TFireRightMouseClick>(Offsets::Instance::FireClickDetector::FireRightMouseClick);

	using TFireMouseHoverEnter = void(__fastcall*)(__int64 a1, __int64 a2);
	inline auto FireMouseHoverEnter = reinterpret_cast<TFireMouseHoverEnter>(Offsets::Instance::FireClickDetector::FireMouseHoverEnter);

	using TFireMouseHoverLeave = void(__fastcall*)(__int64 a1, __int64 a2);
	inline auto FireMouseHoverLeave = reinterpret_cast<TFireMouseHoverLeave>(Offsets::Instance::FireClickDetector::FireMouseHoverLeave);
	
	inline auto TaskDefer = (int(__fastcall*)(lua_State*))Offsets::Functions::TaskDefer;
}


namespace Globals {
	inline lua_State* ExploitThread;
	inline uintptr_t DataModel;

}