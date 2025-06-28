#pragma once

#pragma comment(lib, "shlwapi.lib")

#include "Roblox/Execution/Execution.hpp"
#include <lstate.h>
#include <lualib.h>
#include <lapi.h>
#include <filesystem>
#include <shlwapi.h>
#include <fstream>
#include <future>
#include <cpr/cpr.h>
#include <cryptopp/config_ns.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <nlohmann/json.hpp>
#include "../../../Dependencies/HttpStatus/HttpStatus.hpp"
#include <cpr/cookies.h>
#include <wininet.h>
#include <ldo.h>
#include <lmem.h>
#include <lgc.h>
#include <cryptopp/modes.h>
#include <memory>
#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/rdrand.h>
#include <cryptopp/sha3.h>
#include <cryptopp/md5.h>
#include "Dependencies/lz4/lz4.h"
#include <lfunc.h>
#include "Dependencies/easywsclient/easywsclient.hpp"
#include <unordered_set>
#include <unordered_map>
#include <map>
#include <set>
#include "Roblox/Manager/Manager.hpp"
#include "Roblox/Utils/Util.hpp"
#include "TaskScheduler/TaskScheduler.hpp"
#include <zstd.h>
#include "Dependencies/zstd/include/zstd/xxhash.h"


#pragma comment(lib, "wininet.lib")

#define isdead(g, obj) (((obj)->gch.marked & (g)->currentwhite) == 0)

#undef min
#undef max
#include <algorithm>
#pragma once
#include <iostream>
#include <vector>
#include <array>
#include <sstream>
#include <iomanip>
#include <cstdint>

class SHA256 {
public:
	static std::string hash(const std::string& input) {
		SHA256 sha;
		sha.process(input);
		return sha.finalize();
	}

private:
	static constexpr std::array<uint32_t, 8> H_INIT = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};

	static constexpr std::array<uint32_t, 64> K = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	std::array<uint32_t, 8> hash_values = H_INIT;
	std::vector<uint8_t> buffer;
	uint64_t total_bits = 0;

	static uint32_t rotate_right(uint32_t x, uint32_t n) {
		return (x >> n) | (x << (32 - n));
	}

	static uint32_t sigma0(uint32_t x) {
		return rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3);
	}

	static uint32_t sigma1(uint32_t x) {
		return rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10);
	}

	static uint32_t sum0(uint32_t x) {
		return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22);
	}

	static uint32_t sum1(uint32_t x) {
		return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25);
	}

	static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
		return (x & y) ^ (~x & z);
	}

	static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
		return (x & y) ^ (x & z) ^ (y & z);
	}

	void process(const std::string& input) {
		buffer.assign(input.begin(), input.end());
		total_bits = buffer.size() * 8;
		buffer.push_back(0x80);
		while ((buffer.size() + 8) % 64 != 0) {
			buffer.push_back(0);
		}
		for (int i = 7; i >= 0; --i) {
			buffer.push_back((total_bits >> (i * 8)) & 0xFF);
		}
		process_blocks();
	}

	void process_blocks() {
		for (size_t i = 0; i < buffer.size(); i += 64) {
			std::array<uint32_t, 64> w = {};
			for (size_t j = 0; j < 16; ++j) {
				w[j] = (buffer[i + j * 4] << 24) | (buffer[i + j * 4 + 1] << 16) |
					(buffer[i + j * 4 + 2] << 8) | (buffer[i + j * 4 + 3]);
			}
			for (size_t j = 16; j < 64; ++j) {
				w[j] = sigma1(w[j - 2]) + w[j - 7] + sigma0(w[j - 15]) + w[j - 16];
			}
			std::array<uint32_t, 8> h = hash_values;
			for (size_t j = 0; j < 64; ++j) {
				uint32_t t1 = h[7] + sum1(h[4]) + ch(h[4], h[5], h[6]) + K[j] + w[j];
				uint32_t t2 = sum0(h[0]) + maj(h[0], h[1], h[2]);
				h[7] = h[6]; h[6] = h[5]; h[5] = h[4];
				h[4] = h[3] + t1; h[3] = h[2]; h[2] = h[1]; h[1] = h[0];
				h[0] = t1 + t2;
			}
			for (size_t j = 0; j < 8; ++j) {
				hash_values[j] += h[j];
			}
		}
	}

	std::string finalize() {
		std::ostringstream result;
		for (auto value : hash_values) {
			result << std::hex << std::setw(8) << std::setfill('0') << value;
		}
		return result.str();
	}
};

namespace fs = std::filesystem;

static std::vector<std::string> disallowedExtensions =
{
	".exe", ".scr", ".bat", ".com", ".csh", ".msi", ".vb", ".vbs", ".vbe", ".ws", ".wsf", ".wsh", ".ps1"
};

inline bool equals_ignore_case(const std::string& a, const std::string& b)
{
	return std::equal(a.begin(), a.end(), b.begin(), b.end(), [](char a, char b) { return tolower(a) == tolower(b); });
}
namespace Handler
{
	inline std::unordered_map<Closure*, Closure*> Newcclosures = {};

	inline std::unordered_map<Closure*, Closure*> HookedFunctions = {};

	inline std::map<Closure*, lua_CFunction> ExecutorClosures = {};

	inline std::unordered_set<Closure*> ExecutorFunctions = {};

	static int ClosuresHandler(lua_State* L)
	{
		auto found = ExecutorClosures.find(curr_func(L));

		if (found != ExecutorClosures.end())
		{
			return found->second(L);
		}

		return 0;
	}

	static lua_CFunction GetClosure(Closure* Closure)
	{
		return ExecutorClosures[Closure];
	}

	static void SetClosure(Closure* Closure, lua_CFunction Function)
	{
		ExecutorClosures[Closure] = Function;
	}


	static void PushClosure(lua_State* L, lua_CFunction Function, const char* debugname, int nup)
	{
		lua_pushcclosurek(L, ClosuresHandler, debugname, nup, 0);
		Closure* closure = *reinterpret_cast<Closure**>(index2addr(L, -1));
		ExecutorClosures[closure] = Function;
	}

	static void PushWrappedClosure(lua_State* L, lua_CFunction Function, const char* debugname, int nup, lua_Continuation count)
	{
		lua_pushcclosurek(L, ClosuresHandler, debugname, nup, count);
		Closure* closure = *reinterpret_cast<Closure**>(index2addr(L, -1));
		ExecutorClosures[closure] = Function;
		Handler::ExecutorFunctions.insert(closure);
		lua_ref(L, -1);
	}


	namespace Wraps
	{
		static Closure* GetClosure(Closure* c)
		{
			return Newcclosures.find(c)->second;
		}

		static void SetClosure(Closure* c, Closure* l)
		{
			Newcclosures[c] = l;
		}
	}
}
namespace Filesystem {
	static std::filesystem::path localAppdata = getenv("LOCALAPPDATA");
	static std::filesystem::path realLibrary = localAppdata / "CLDY";
	static std::filesystem::path workspace = realLibrary / "Workspace";





	inline int readfile(lua_State* L) {
		if (!fs::exists(workspace)) {
			std::error_code ec;
			fs::create_directories(workspace, ec);
			return readfile(L);
		}

		luaL_checktype(L, 1, LUA_TSTRING);



		std::string path = lua_tostring(L, 1);
		std::replace(path.begin(), path.end(), '/', '\\');
		if (path.find("..") != std::string::npos) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "attempt to escape directory");
			lua_call(L, 1, 0);
			return 0;
		}

		std::filesystem::path workspacePath = workspace / path;
		const std::string extension = PathFindExtension(path.data());

		FILE* file = fopen(workspacePath.string().c_str(), "rb");
		if (!file) {
			luaL_error(L, "file does not exist!");
			return 0;
		}



		fseek(file, 0, SEEK_END);
		size_t fileSize = ftell(file);
		rewind(file);

		std::string content(fileSize, '\0');
		size_t bytesread = fread(&content[0], 1, fileSize, file);
		fclose(file);

		lua_pushstring(L, content.data());

		return 1;
	}

	inline int listfiles(lua_State* L) {
		if (!fs::exists(workspace)) {
			std::error_code ec;
			fs::create_directories(workspace, ec);
			return listfiles(L);
		}
		luaL_checktype(L, 1, LUA_TSTRING);

		std::string path = lua_tostring(L, 1);
		std::replace(path.begin(), path.end(), '/', '\\');
		if (path.find("..") != std::string::npos) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "attempt to escape directory");
			lua_call(L, 1, 0);
			return 0;
		}

		std::filesystem::path workspacePath = workspace / path;
		if (!std::filesystem::exists(workspacePath)) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "directory doesn't exist!");
			lua_call(L, 1, 0);
			return 0;
		}

		int index = 0;
		lua_newtable(L);

		for (auto& file : std::filesystem::directory_iterator(workspacePath)) {
			auto filePath = file.path().string().substr(workspace.string().length() + 1);

			lua_pushinteger(L, ++index);
			lua_pushstring(L, filePath.data());
			lua_settable(L, -3);
		}

		return 1;
	}

	inline int writefile(lua_State* L) {
		if (!fs::exists(workspace)) {
			std::error_code ec;
			fs::create_directories(workspace, ec);
			return writefile(L);
		}
		// Validate input arguments
		luaL_checktype(L, 1, LUA_TSTRING);
		luaL_checktype(L, 2, LUA_TSTRING);

		std::string path = lua_tostring(L, 1);
		std::string data = lua_tostring(L, 2);

		// Normalize path separators to the current OS
		std::replace(path.begin(), path.end(), '/', '\\');

		// Prevent directory traversal
		if (path.find("..") != std::string::npos) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "Attempt to escape directory");
			lua_call(L, 1, 0);
			return 0;
		}

		// Construct the full path to the file
		std::filesystem::path workspacePath = workspace / path;

		// Get file extension and check if it is disallowed
		const std::string extension = PathFindExtension(path.c_str());
		for (const std::string& forbidden : disallowedExtensions) {
			if (equals_ignore_case(extension, forbidden)) {
				lua_getglobal(L, "warn");
				lua_pushstring(L, "Forbidden extension!");
				lua_call(L, 1, 0);
				return 0;
			}
		}

		// Check if the file path is too long (e.g., for Windows)
		const size_t maxPathLength = 260; // Common path length limit in Windows
		if (workspacePath.string().length() > maxPathLength) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "Path length exceeds system limit!");
			lua_call(L, 1, 0);
			return 0;
		}

		// Open the file for writing
		std::ofstream file(workspacePath, std::ios::binary);
		if (!file) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "Failed to open file for writing!");
			lua_call(L, 1, 0);
			return 0;
		}

		// Write data to the file in chunks to avoid buffer overflow
		const size_t chunkSize = 1024; // Write in 1 KB chunks
		size_t totalWritten = 0;
		while (totalWritten < data.size()) {
			size_t toWrite = std::min(chunkSize, data.size() - totalWritten);
			file.write(data.data() + totalWritten, toWrite);
			if (!file) {
				lua_getglobal(L, "warn");
				lua_pushstring(L, "Error writing to file!");
				lua_call(L, 1, 0);
				return 0;
			}
			totalWritten += toWrite;
		}

		// Successfully wrote to file
		return 0;
	}

	inline int makefolder(lua_State* L) {
		if (!fs::exists(workspace)) {
			std::error_code ec;
			fs::create_directories(workspace, ec);
			return makefolder(L);
		}
		luaL_checktype(L, 1, LUA_TSTRING);

		std::string path = lua_tostring(L, 1);
		std::replace(path.begin(), path.end(), '/', '\\');
		if (path.find("..") != std::string::npos) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "attempt to escape directory");
			lua_call(L, 1, 0);
			return 0;
		}

		std::filesystem::path workspacePath = workspace / path;
		std::filesystem::create_directory(workspacePath);

		return 0;
	}

	inline int appendfile(lua_State* L) {
		if (!fs::exists(workspace)) {
			std::error_code ec;
			fs::create_directories(workspace, ec);
			return appendfile(L);
		}
		luaL_checktype(L, 1, LUA_TSTRING);
		luaL_checktype(L, 2, LUA_TSTRING);

		std::string path = lua_tostring(L, 1);
		std::string data = lua_tostring(L, 2);

		std::replace(path.begin(), path.end(), '/', '\\');

		if (path.find("..") != std::string::npos) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "attempt to escape directory");
			lua_call(L, 1, 0);
			return 0;
		}

		std::filesystem::path workspacePath = workspace / path;

		std::string extension = PathFindExtension(path.c_str());

		for (const std::string& forbidden : disallowedExtensions) {
			if (equals_ignore_case(extension, forbidden)) {
				lua_getglobal(L, "warn");
				lua_pushstring(L, "forbidden extension!");
				lua_call(L, 1, 0);
				return 0;
			}
		}

		std::ofstream outFile(workspacePath, std::ios::app | std::ios::binary);
		if (!outFile.is_open()) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "failed to open file for appending");
			lua_call(L, 1, 0);
			return 0;
		}

		outFile.write(data.data(), data.size());

		if (!outFile) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "error while writing to file");
			lua_call(L, 1, 0);
		}

		outFile.close();
		return 0;
	}

	inline int isfile(lua_State* L) {
		if (!fs::exists(workspace)) {
			luaL_error(L, "Workspace not initialized.");
			return 0;
		}
		luaL_checktype(L, 1, LUA_TSTRING);

		std::string path = lua_tostring(L, 1);
		std::replace(path.begin(), path.end(), '/', '\\');
		if (path.find("..") != std::string::npos) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "attempt to escape directory");
			lua_call(L, 1, 0);
			return 0;
		}

		std::filesystem::path workspacePath = workspace / path;

		lua_pushboolean(L, std::filesystem::is_regular_file(workspacePath));

		return 1;
	}

	inline int isfolder(lua_State* L) {
		if (!fs::exists(workspace)) {
			std::error_code ec;
			fs::create_directories(workspace, ec);
			return isfolder(L);
		}
		luaL_checktype(L, 1, LUA_TSTRING);

		std::string path = lua_tostring(L, 1);
		std::replace(path.begin(), path.end(), '/', '\\');
		if (path.find("..") != std::string::npos) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "attempt to escape directory");
			lua_call(L, 1, 0);
			return 0;
		}

		std::filesystem::path workspacePath = workspace / path;

		lua_pushboolean(L, std::filesystem::is_directory(workspacePath));

		return 1;
	}

	inline int delfolder(lua_State* L) {
		if (!fs::exists(workspace)) {
			std::error_code ec;
			fs::create_directories(workspace, ec);
			return delfolder(L);
		}
		luaL_checktype(L, 1, LUA_TSTRING);

		std::string path = lua_tostring(L, 1);
		std::replace(path.begin(), path.end(), '/', '\\');
		if (path.find("..") != std::string::npos) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "attempt to escape directory");
			lua_call(L, 1, 0);
			return 0;
		}

		std::filesystem::path workspacePath = workspace / path;
		if (!std::filesystem::remove_all(workspacePath)) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "folder does not exist!");
			lua_call(L, 1, 0);
			return 0;
		}

		return 0;
	}

	inline int delfile(lua_State* L) {
		if (!fs::exists(workspace)) {
			std::error_code ec;
			fs::create_directories(workspace, ec);
			return delfile(L);
		}
		luaL_checktype(L, 1, LUA_TSTRING);

		std::string path = lua_tostring(L, 1);
		std::replace(path.begin(), path.end(), '/', '\\');
		if (path.find("..") != std::string::npos) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "attempt to escape directory");
			lua_call(L, 1, 0);
			return 0;
		}

		std::filesystem::path workspacePath = workspace / path;
		if (!std::filesystem::remove(workspacePath)) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "file does not exist!");
			lua_call(L, 1, 0);
			return 0;
		}

		return 0;
	}

	inline int loadfile(lua_State* L) {
		if (!fs::exists(workspace)) {
			std::error_code ec;
			fs::create_directories(workspace, ec);
			return loadfile(L);
		}
		luaL_checktype(L, 1, LUA_TSTRING);

		std::string path = lua_tostring(L, 1);
		const std::string chunkname = luaL_optstring(L, 2, "=");
		std::replace(path.begin(), path.end(), '/', '\\');
		if (path.find("..") != std::string::npos) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "attempt to escape directory");
			lua_call(L, 1, 0);
			return 0;
		}

		std::filesystem::path workspacePath = workspace / path;

		FILE* file = fopen(workspacePath.string().c_str(), "rb");
		if (!file) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "file does not exist!");
			lua_call(L, 1, 0);
			return 0;
		}

		fseek(file, 0, SEEK_END);
		size_t fileSize = ftell(file);
		rewind(file);

		std::string content(fileSize, '\0');
		size_t bytesread = fread(&content[0], 1, fileSize, file);
		fclose(file);

		std::string script = Execution->CompileScript(content, LUAVM_LOAD);
		if (script[0] == '\0' || script.empty()) {
			lua_pushnil(L);
			lua_pushstring(L, "Failed to compile script");
			return 2;
		}

		int result = RBX::LuaVM__Load(L, &script, chunkname.data(), 0);
		if (result != LUA_OK) {
			std::string Error = luaL_checklstring(L, -1, nullptr);
			lua_pop(L, 1);

			lua_pushnil(L);
			lua_pushstring(L, Error.data());

			return 2;
		}

		Closure* closure = clvalue(luaA_toobject(L, -1));
		TaskScheduler::SetProtoCapabilities(closure->l.p);
		return 1;
	}

	inline int dofile(lua_State* L) {
		if (!fs::exists(workspace)) {
			std::error_code ec;
			fs::create_directories(workspace, ec);
			return dofile(L);
		}
		luaL_checktype(L, 1, LUA_TSTRING);

		std::string path = lua_tostring(L, 1);
		std::replace(path.begin(), path.end(), '/', '\\');
		if (path.find("..") != std::string::npos) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "attempt to escape directory");
			lua_call(L, 1, 0);
			return 0;
		}

		std::filesystem::path workspacePath = workspace / path;

		FILE* file = fopen(workspacePath.string().c_str(), "rb");
		if (!file) {
			lua_getglobal(L, "warn");
			lua_pushstring(L, "file does not exist!");
			lua_call(L, 1, 0);
			return 0;
		}

		fseek(file, 0, SEEK_END);
		size_t fileSize = ftell(file);
		rewind(file);

		std::string content(fileSize, '\0');
		size_t bytesread = fread(&content[0], 1, fileSize, file);
		fclose(file);

		std::string script = Execution->CompileScript(content, LUAVM_LOAD);
		if (script[0] == '\0' || script.empty()) {
			lua_pushnil(L);
			lua_pushstring(L, "Failed to compile script");
			return 2;
		}

		int result = RBX::LuaVM__Load(L, &script, "=", 0);
		if (result != LUA_OK) {
			std::string Error = luaL_checklstring(L, -1, nullptr);
			lua_pop(L, 1);

			lua_pushnil(L);
			lua_pushstring(L, Error.data());

			return 2;
		}

		Closure* closure = clvalue(luaA_toobject(L, -1));

		TaskScheduler::SetProtoCapabilities(closure->l.p);

		RBX::Task__Defer(L);

		return 0;
	}

	inline int getcustomasset(lua_State* L) {
		if (!fs::exists(workspace)) {
			luaL_error(L, "Workspace not initialized.");
			return 0;
		}

		luaL_checktype(L, 1, LUA_TSTRING);
		const std::string FileName = lua_tostring(L, 1);

		const auto FilePath = workspace / FileName;
		if (!std::filesystem::exists(FilePath)) {
			luaL_error(L, "File not found: %s", FileName.c_str());
			return 0;
		}

		const auto SoundDir = std::filesystem::current_path() / "content" / "sounds";
		std::filesystem::create_directories(SoundDir);

		const auto AssetPath = SoundDir / FilePath.filename();

		const auto ContentSize = std::filesystem::file_size(FilePath);
		std::string Result;
		Result.resize(ContentSize);

		std::ifstream In(FilePath, std::ios::binary);
		In.read(Result.data(), ContentSize);
		In.close();

		std::ofstream Out(AssetPath, std::ios::binary);
		Out.write(Result.data(), Result.size());
		Out.close();

		const std::string SoundId = std::format("rbxasset://sounds/{}", AssetPath.filename().string());
		lua_pushstring(L, SoundId.c_str());
		return 1;
	}

}

namespace HelpFuncs {
	using YieldReturn = std::function<int(lua_State* L)>;

	static void ThreadFunc(const std::function<YieldReturn()>& YieldedFunction, lua_State* L)
	{
		YieldReturn ret_func;

		try
		{
			ret_func = YieldedFunction();
		}
		catch (std::exception ex)
		{
			lua_pushstring(L, ex.what());
			lua_error(L);
		}

		lua_State* l_new = lua_newthread(L);

		const auto returns = ret_func(L);

		lua_getglobal(l_new, ("task"));
		lua_getfield(l_new, -1, ("defer"));

		lua_pushthread(L);
		lua_xmove(L, l_new, 1);

		for (int i = returns; i >= 1; i--)
		{
			lua_pushvalue(L, -i);
			lua_xmove(L, l_new, 1);
		}

		lua_pcall(l_new, returns + 1, 0, 0);
		lua_settop(l_new, 0);
	}

	static int YieldExecution(lua_State* L, const std::function<YieldReturn()>& YieldedFunction)
	{
		lua_pushthread(L);
		lua_ref(L, -1);
		lua_pop(L, 1);

		std::thread(ThreadFunc, YieldedFunction, L).detach();

		L->base = L->top;
		L->status = LUA_YIELD;

		L->ci->flags |= 1;
		return -1;
	}

	static void IsInstance(lua_State* L, int idx) {
		std::string typeoff = luaL_typename(L, idx);
		if (typeoff != ("Instance"))
			luaL_typeerrorL(L, 1, ("Instance"));
	};

	static bool IsClassName(lua_State* L, int idx, std::string className) {
		int originalArgCount = lua_gettop(L);

		if (lua_isnil(L, idx)) {
			return false;
		}

		lua_getglobal(L, ("typeof"));
		lua_pushvalue(L, idx);
		lua_pcall(L, 1, 1, 0);

		std::string resultType = luaL_checklstring(L, -1, nullptr);
		lua_pop(L, lua_gettop(L) - originalArgCount);

		if (resultType != ("Instance")) {
			return false;
		}

		lua_getfield(L, idx, "ClassName");
		std::string object_ClassName = luaL_checklstring(L, -1, nullptr);
		lua_pop(L, lua_gettop(L) - originalArgCount);

		lua_getfield(L, idx, ("IsA"));
		lua_pushvalue(L, idx);
		lua_pushlstring(L, className.data(), className.size());
		lua_pcall(L, 2, 1, 0);

		bool isAResult = lua_isboolean(L, -1) ? lua_toboolean(L, -1) : false;
		lua_pop(L, lua_gettop(L) - originalArgCount);

		if (!isAResult & object_ClassName != className)
			return false;

		return true;
	};

	static int GetEveryInstance(lua_State* L)
	{
		lua_pushvalue(L, LUA_REGISTRYINDEX);
		lua_pushlightuserdata(L, (void*)Offsets::Functions::PushInstance);
		lua_gettable(L, -2);
		return 1;
	};

	static uintptr_t GetPlaceId() {
		return 0;
	}

	static uintptr_t GetGameId() {
		return 0;
	}

	static std::string DecompressBytecode(const std::string_view compressed) {
		const uint8_t bytecodeSignature[4] = { 'R', 'S', 'B', '1' };
		const int bytecodeHashMultiplier = 41;
		const int bytecodeHashSeed = 42;

		if (compressed.size() < 8)
			return "invalid bytecode: size is less than 8";

		std::vector<uint8_t> compressedData(compressed.begin(), compressed.end());
		std::vector<uint8_t> headerBuffer(4);

		for (size_t i = 0; i < 4; ++i) {
			headerBuffer[i] = compressedData[i] ^ bytecodeSignature[i];
			headerBuffer[i] = (headerBuffer[i] - i * bytecodeHashMultiplier) % 256;
		}

		for (size_t i = 0; i < compressedData.size(); ++i) {
			compressedData[i] ^= (headerBuffer[i % 4] + i * bytecodeHashMultiplier) % 256;
		}

		uint32_t hashValue = 0;
		for (size_t i = 0; i < 4; ++i) {
			hashValue |= headerBuffer[i] << (i * 8);
		}

		uint32_t rehash = XXH32(compressedData.data(), compressedData.size(), bytecodeHashSeed);
		if (rehash != hashValue)
			return "";

		uint32_t decompressedSize = 0;
		for (size_t i = 4; i < 8; ++i) {
			decompressedSize |= compressedData[i] << ((i - 4) * 8);
		}

		compressedData = std::vector<uint8_t>(compressedData.begin() + 8, compressedData.end());
		std::vector<uint8_t> decompressed(decompressedSize);

		size_t const actualDecompressedSize = ZSTD_decompress(decompressed.data(), decompressedSize, compressedData.data(), compressedData.size());
		if (ZSTD_isError(actualDecompressedSize))
			return "zstd decompress error: " + std::string(ZSTD_getErrorName(actualDecompressedSize));

		decompressed.resize(actualDecompressedSize);
		return std::string(decompressed.begin(), decompressed.end());
	}

	static std::string GetBytecode(std::uint64_t Address) {
		uintptr_t str = Address + 0x10;
		uintptr_t data;

		if (*reinterpret_cast<std::size_t*>(str + 0x18) > 0xf) {
			data = *reinterpret_cast<uintptr_t*>(str);
		}
		else {
			data = str;
		}

		std::string ee;
		std::size_t len = *reinterpret_cast<std::size_t*>(str + 0x10);
		ee.reserve(len);

		for (unsigned i = 0; i < len; i++) {
			ee += *reinterpret_cast<char*>(data + i);
		}

		return ee;
	}

	static std::string RequestBytecode(uintptr_t scriptPtr, bool Decompress) {
		uintptr_t temp[0x4];
		std::memset(temp, 0, sizeof(temp));

		RBX::RequestCode((uintptr_t)temp, scriptPtr);

		uintptr_t bytecodePtr = temp[1];

		if (!bytecodePtr) {
			return "Nil";
		}

		std::string Compressed = GetBytecode(bytecodePtr);
		if (Compressed.size() <= 8) {
			return "Nil";
		}

		if (!Decompress)
		{
			return Compressed;
		}
		else
		{
			std::string Decompressed = DecompressBytecode(Compressed);
			if (Decompressed.size() <= 8) {
				return "Nil";
			}

			return Decompressed;
		}
	}

}


struct base_t;

template< class t >
class c_storage
{
	std::mutex m_l;

protected:
	t m_container;
public:

	auto safe_request(auto request, auto... args)
	{
		std::unique_lock l{ m_l };

		return request(args...);
	};

	void clear()
	{
		safe_request([&]()
			{ m_container.clear(); });
	}
};

using block_cache_t
= std::unordered_map< void*,
	bool >;

class c_blocked : public c_storage< block_cache_t >
{
public:
	inline void toggle(void* connection, bool enabled)
	{
		safe_request([&]()
			{
				m_container[connection] = enabled;
			});
	}

	inline bool should_block(void* connection)
	{
		return safe_request([&]()
			{
				return m_container.contains(connection)
					? !m_container[connection] : false;
			});
	}

} inline g_blocked;

using instance_cache_t
= std::unordered_map< void*,
	std::unordered_map< std::string, bool > >;

class c_instance_cache : public c_storage< instance_cache_t >
{
public:
	inline void toggle(void* instance, const std::string& prop, bool enabled)
	{
		safe_request([&]()
			{
				m_container[instance][prop] = enabled;
			});
	}

	inline std::optional< bool > is_scripLuaTable(void* instance, const std::string& prop)
	{
		return safe_request([&]() -> std::optional< bool >
			{
				if (m_container.contains(instance))
				{
					const auto properties = m_container[instance];

					if (properties.contains(prop))
						return properties.at(prop);
				}

				return std::nullopt;
			});
	}
} inline g_instance;

using closure_cache_t
= std::vector< void* >;

class c_closure_cache : public c_storage< closure_cache_t >
{
public:
	inline void add(void* closure)
	{
		safe_request([&]()
			{
				m_container.push_back(closure);
			});
	}

	inline bool contains(void* closure)
	{
		return safe_request([&]() -> bool
			{
				return std::find(m_container.begin(), m_container.end(), closure) != m_container.end();
			});
	}
} inline g_closure_cache;

using newcclosure_cache_t = std::unordered_map< Closure*, Closure* >;

static class c_newcclosure_cache : public c_storage< newcclosure_cache_t >
{
public:
	inline void add(Closure* cclosure, Closure* lclosure)
	{
		safe_request([&]()
			{
				m_container[cclosure] = lclosure;
			});
	}

	inline void remove(Closure* obj)
	{
		safe_request([&]()
			{
				auto it = m_container.find(obj);
				if (it != m_container.end())
					m_container.erase(it);
			});
	}

	inline std::optional< Closure* > get(Closure* closure)
	{
		return safe_request([&]() -> std::optional< Closure* >
			{
				if (m_container.contains(closure))
					return m_container.at(closure);

				return std::nullopt;
			});
	}
} inline g_newcclosure_cache;

static void handler_run(lua_State* L, void* ud) {
	luaD_call(L, (StkId)(ud), LUA_MULTRET);
}

inline int handler_continuation(lua_State* L, std::int32_t status) {
	if (status != LUA_OK) {
		std::string regexed_error = lua_tostring(L, -1);
		lua_pop(L, 1);

		lua_pushlstring(L, regexed_error.c_str(), regexed_error.size());
		lua_error(L);
	}

	return lua_gettop(L);
};



namespace Crypt {

	namespace HelpFunctions {

		template<typename T>
		static std::string hash_with_algo(const std::string& Input)
		{
			T Hash;
			std::string Digest;

			CryptoPP::StringSource SS(Input, true,
				new CryptoPP::HashFilter(Hash,
					new CryptoPP::HexEncoder(
						new CryptoPP::StringSink(Digest), false
					)));

			return Digest;
		}
		inline std::string b64encode(const std::string& stringToEncode) {
			std::string base64EncodedString;
			CryptoPP::Base64Encoder encoder{ new CryptoPP::StringSink(base64EncodedString), false };
			encoder.Put((byte*)stringToEncode.c_str(), stringToEncode.length());
			encoder.MessageEnd();

			return base64EncodedString;
		}

		inline std::string b64decode(const std::string& stringToDecode) {
			std::string base64DecodedString;
			CryptoPP::Base64Decoder decoder{ new CryptoPP::StringSink(base64DecodedString) };
			decoder.Put((byte*)stringToDecode.c_str(), stringToDecode.length());
			decoder.MessageEnd();

			return base64DecodedString;
		}

		inline std::string RamdonString(int len) {
			static const char* chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
			std::string str;
			str.reserve(len);

			for (int i = 0; i < len; ++i) {
				str += chars[rand() % (strlen(chars) - 1)];
			}

			return str;
		}
	}

	static enum HashModes
	{
		//MD5
		MD5,

		//SHA1
		SHA1,

		//SHA2
		SHA224,
		SHA256,
		SHA384,
		SHA512,

		//SHA3
		SHA3_224,
		SHA3_256,
		SHA3_384,
		SHA3_512,
	};

	static std::map<std::string, HashModes> HashTranslationMap = {
		//MD5
		{ "md5", MD5 },

		//SHA1
		{ "sha1", SHA1 },

		//SHA2
		{ "sha224", SHA224 },
		{ "sha256", SHA256 },
		{ "sha384", SHA384 },
		{ "sha512", SHA512 },

		//SHA3
		{ "sha3-224", SHA3_224 },
		{ "sha3_224", SHA3_224 },
		{ "sha3-256", SHA3_256 },
		{ "sha3_256", SHA3_256 },
		{ "sha3-384", SHA3_384 },
		{ "sha3_384", SHA3_384 },
		{ "sha3-512", SHA3_512 },
		{ "sha3_512", SHA3_512 },
	};

	inline int base64encode(lua_State* L) {
		//("crypt.base64encode");

		luaL_checktype(L, 1, LUA_TSTRING);
		size_t stringLength;
		const char* rawStringToEncode = lua_tolstring(L, 1, &stringLength);
		const std::string stringToEncode(rawStringToEncode, stringLength);
		const std::string encodedString = HelpFunctions::b64encode(stringToEncode);

		lua_pushlstring(L, encodedString.c_str(), encodedString.size());
		return 1;
	}

	inline int base64decode(lua_State* L) {
		//("crypt.base64decode");

		luaL_checktype(L, 1, LUA_TSTRING);
		size_t stringLength;
		const char* rawStringToDecode = lua_tolstring(L, 1, &stringLength);
		const auto stringToDecode = std::string(rawStringToDecode, stringLength);
		const std::string decodedString = HelpFunctions::b64decode(stringToDecode);

		lua_pushlstring(L, decodedString.c_str(), decodedString.size());
		return 1;
	}

	inline int generatebytes(lua_State* L) {
		//("crypt.generatebytes");

		luaL_checktype(L, 1, LUA_TNUMBER);
		const auto bytesSize = lua_tointeger(L, 1);

		CryptoPP::RDRAND rng;
		const auto bytesBuffer = new byte[bytesSize];
		rng.GenerateBlock(bytesBuffer, bytesSize);

		std::string base64EncodedBytes;
		CryptoPP::Base64Encoder encoder{ new CryptoPP::StringSink(base64EncodedBytes), false };
		encoder.Put(bytesBuffer, bytesSize);
		encoder.MessageEnd();

		delete bytesBuffer;
		lua_pushlstring(L, base64EncodedBytes.c_str(), base64EncodedBytes.size());
		return 1;
	}

	inline int generatekey(lua_State* L) {
		//("crypt.generatekey");

		const auto bytesBuffer = new byte[CryptoPP::AES::MAX_KEYLENGTH];

		CryptoPP::RDRAND rng;
		rng.GenerateBlock(bytesBuffer, CryptoPP::AES::MAX_KEYLENGTH);

		std::string base64EncodedBytes;
		CryptoPP::Base64Encoder encoder{ new CryptoPP::StringSink(base64EncodedBytes), false };
		encoder.Put(bytesBuffer, CryptoPP::AES::MAX_KEYLENGTH);
		encoder.MessageEnd();

		delete bytesBuffer;
		lua_pushlstring(L, base64EncodedBytes.c_str(), base64EncodedBytes.size());
		return 1;
	}

	inline int hash(lua_State* L) {
		//("crypt.hash");

		std::string algo = luaL_checklstring(L, 2, NULL);
		std::string data = luaL_checklstring(L, 1, NULL);

		std::transform(algo.begin(), algo.end(), algo.begin(), tolower);

		if (!HashTranslationMap.count(algo))
		{
			luaL_argerror(L, 1, "non-existant hash algorithm");
			return 0;
		}

		const auto ralgo = HashTranslationMap[algo];

		std::string hash;

		if (ralgo == MD5) {
			hash = HelpFunctions::hash_with_algo<CryptoPP::MD5>(data);
		}
		else if (ralgo == SHA1) {
			hash = HelpFunctions::hash_with_algo<CryptoPP::SHA1>(data);
		}
		else if (ralgo == SHA224) {
			hash = HelpFunctions::hash_with_algo<CryptoPP::SHA224>(data);
		}
		else if (ralgo == SHA256) {
			hash = HelpFunctions::hash_with_algo<CryptoPP::SHA256>(data);
		}
		else if (ralgo == SHA384) {
			hash = HelpFunctions::hash_with_algo<CryptoPP::SHA384>(data);
		}
		else if (ralgo == SHA512) {
			hash = HelpFunctions::hash_with_algo<CryptoPP::SHA512>(data);
		}
		else if (ralgo == SHA3_224) {
			hash = HelpFunctions::hash_with_algo<CryptoPP::SHA3_224>(data);
		}
		else if (ralgo == SHA3_256) {
			hash = HelpFunctions::hash_with_algo<CryptoPP::SHA3_256>(data);
		}
		else if (ralgo == SHA3_384) {
			hash = HelpFunctions::hash_with_algo<CryptoPP::SHA3_384>(data);
		}
		else if (ralgo == SHA3_512) {
			hash = HelpFunctions::hash_with_algo<CryptoPP::SHA3_512>(data);
		}
		else {
			luaL_argerror(L, 1, "non-existant hash algorithm");
			return 0;
		}

		lua_pushlstring(L, hash.c_str(), hash.size());

		return 1;
	}
	using ModePair = std::pair<std::unique_ptr<CryptoPP::CipherModeBase>, std::unique_ptr<CryptoPP::CipherModeBase> >;

	inline std::optional<ModePair> getEncryptionDecryptionMode(const std::string& modeName) {
		if (modeName == "cbc") {
			//("Mode:cbc");
			return ModePair{
				std::make_unique<CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption>(),
				std::make_unique<CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption>()
			};
		}
		else if (modeName == "cfb") {
			return ModePair{
				std::make_unique<CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption>(),
				std::make_unique<CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption>()
			};
		}
		else if (modeName == "ofb") {
			return ModePair{
				std::make_unique<CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption>(),
				std::make_unique<CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption>()
			};
		}
		else if (modeName == "ctr") {
			return ModePair{
				std::make_unique<CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption>(),
				std::make_unique<CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption>()
			};
		}
		else if (modeName == "ecb") {
			return ModePair{
				std::make_unique<CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption>(),
				std::make_unique<CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption>()
			};
		}
		else {
			return std::nullopt;
		}
	}

	inline int encrypt(lua_State* L) {
		luaL_checktype(L, 1, LUA_TSTRING);
		luaL_checktype(L, 2, LUA_TSTRING);

		const auto rawDataString = lua_tostring(L, 1);
		lua_pushstring(L, HelpFunctions::b64encode(rawDataString).c_str());
		lua_pushstring(L, "");

		return 2;
	}

	inline int decrypt(lua_State* L) {
		luaL_checktype(L, 1, LUA_TSTRING);
		luaL_checktype(L, 2, LUA_TSTRING);
		luaL_checktype(L, 3, LUA_TSTRING);
		luaL_checktype(L, 4, LUA_TSTRING);

		const auto rawDataString = lua_tostring(L, 1);
		lua_pushstring(L, HelpFunctions::b64decode(rawDataString).c_str());
		return 1;
	}
};

namespace InstancesHelper {
	inline bool luau_isscriptable(uintptr_t Property)
	{
		auto scriptable = *reinterpret_cast<uintptr_t*>(Property + 0x48);
		return scriptable & 0x20;
	};

	inline void luau_setscriptable(uintptr_t property, bool enabled)
	{
		*reinterpret_cast<uintptr_t*>(property + 0x48) = enabled ? 0xFF : 0x0;
	};

	inline  std::unordered_map<std::string, uintptr_t> GetInstanceProperties(const uintptr_t rawInstance) {
		auto foundProperties = std::unordered_map<std::string, uintptr_t>();

		const auto classDescriptor = *reinterpret_cast<uintptr_t*>(
			rawInstance + Offsets::Properties::ClassDescriptor);
		const auto allPropertiesStart = *reinterpret_cast<uintptr_t*>(
			classDescriptor + 0x30);
		const auto allPropertiesEnd = *reinterpret_cast<uintptr_t*>(
			classDescriptor + 0x38);

		for (uintptr_t currentPropertyAddress = allPropertiesStart; currentPropertyAddress != allPropertiesEnd;
			currentPropertyAddress += 0x8) {
			const auto currentProperty = *reinterpret_cast<uintptr_t*>(currentPropertyAddress);
			const auto propertyNameAddress = *reinterpret_cast<uintptr_t*>(
				currentProperty + 0x8);
			if (propertyNameAddress == 0)
				continue;
			const auto propertyName = *reinterpret_cast<std::string*>(propertyNameAddress);
			foundProperties[propertyName] = currentProperty;
		}

		return foundProperties;
	}
};
static std::vector<std::tuple<uintptr_t, std::string, bool>> script_able_cache;
static std::vector<std::pair<std::string, bool>> default_property_states;

inline int getCachedScriptableProperty(uintptr_t instance, std::string property) {
	for (auto& cacheData : script_able_cache) {
		uintptr_t instanceAddress = std::get<0>(cacheData);
		std::string instanceProperty = std::get<1>(cacheData);

		if (instanceAddress == instance && instanceProperty == property) {
			return std::get<2>(cacheData);
		}
	}

	return -1;
};

inline int getCachedDefultScriptableProperty(std::string property) {
	for (auto& cacheData : default_property_states) {
		if (cacheData.first == property) {
			return cacheData.second;
		}
	}

	return -1;
};

inline bool findAndUpdateScriptAbleCache(uintptr_t instance, std::string property, bool state) {
	for (auto& cacheData : script_able_cache) {
		uintptr_t instanceAddress = std::get<0>(cacheData);
		std::string instanceProperty = std::get<1>(cacheData);

		if (instanceAddress == instance && instanceProperty == property) {
			std::get<2>(cacheData) = state;
			return true;
		}
	}

	return false;
}

inline void addDefaultPropertyState(std::string property, bool state) {
	bool hasDefault = false;

	for (auto& cacheData : default_property_states) {
		if (cacheData.first == property) {
			hasDefault = true;
			break;
		}
	}

	if (!hasDefault) {
		default_property_states.push_back({ property, state });
	}
}


namespace Misc {


	inline int detections(lua_State* L) {
		uintptr_t moduleBase = reinterpret_cast<uintptr_t>(GetModuleHandle("RobloxPlayerBeta.dll"));
		uintptr_t yaraBase = moduleBase + Offsets::Yara::YaraBase;
		uintptr_t addrbadcert = yaraBase + Offsets::Yara::BAD_CERTIFICATE;
		uintptr_t addrNeutral = yaraBase + Offsets::Yara::SCAN_NEUTRAL;
		uintptr_t addrSuspicious = yaraBase + Offsets::Yara::SUSPICIOUS;
		uintptr_t addrLikelyMal = yaraBase + Offsets::Yara::LIKELY_MALICIOUS;
		uintptr_t addrMalicious = yaraBase + Offsets::Yara::MALICIOUS;

		uint32_t addrtbadcert = *reinterpret_cast<uint32_t*>(addrbadcert);
		uint32_t addrtneutral = *reinterpret_cast<uint32_t*>(addrNeutral);
		uint32_t addrsus = *reinterpret_cast<uint32_t*>(addrSuspicious);
		uint32_t addrlm = *reinterpret_cast<uint32_t*>(addrLikelyMal);
		uint32_t addrm = *reinterpret_cast<uint32_t*>(addrMalicious);
		RBX::Print(0, "Yara detections:");
		RBX::Print(0, "Bad Certificate: %d", addrtbadcert);
		RBX::Print(0, "Scan Neutral: %d", addrtneutral);
		RBX::Print(0, "Suspicious: %d", addrsus);
		RBX::Print(0, "Likely Malicious: %d", addrlm);
		RBX::Print(0, "Malicious: %d", addrm);
		lua_newtable(L);

		lua_pushstring(L, "bad_certificate");
		lua_pushinteger(L, addrtbadcert);
		lua_settable(L, -3);

		lua_pushstring(L, "scan_neutral");
		lua_pushinteger(L, addrtneutral);
		lua_settable(L, -3);

		lua_pushstring(L, "suspicious");
		lua_pushinteger(L, addrsus);
		lua_settable(L, -3);

		lua_pushstring(L, "likely_malicious");
		lua_pushinteger(L, addrlm);
		lua_settable(L, -3);

		lua_pushstring(L, "malicious");
		lua_pushinteger(L, addrm);
		lua_settable(L, -3);

		return 1;
	}


	inline int getfunctionhash(lua_State* L) {
		luaL_checktype(L, 1, LUA_TFUNCTION);

		Closure* cl = (Closure*)lua_topointer(L, 1);

		// closure info
		uint8_t nupvalues = cl->nupvalues;
		Proto* p = (Proto*)cl->l.p;

		std::string result =
			std::to_string((int)p->sizep) + "," +
			std::to_string((int)p->sizelocvars) + "," +
			std::to_string((int)p->sizeupvalues) + "," +
			std::to_string((int)p->sizek) + "," +
			std::to_string((int)p->sizelineinfo) + "," +
			std::to_string((int)p->linegaplog2) + "," +
			std::to_string((int)p->linedefined) + "," +
			std::to_string((int)p->bytecodeid) + "," +
			std::to_string((int)p->sizetypeinfo) + "," +
			std::to_string(nupvalues);

		std::string hash = SHA256::hash(result);

		lua_pushstring(L, hash.c_str());

		return 1;
	}

	inline int messagebox(lua_State* LS) {
		const auto text = luaL_checkstring(LS, 1);
		const auto caption = luaL_checkstring(LS, 2);
		const auto type = luaL_checkinteger(LS, 3);
		std::ostringstream ss;
		ss << "[Cloudy] " << caption;
		MessageBoxA(nullptr, text, ss.str().c_str(), type);
		return 0;
	}

	inline int getexecutorname(lua_State* LS) {
		lua_pushstring(LS, "CLOUDY");
		return 1;
	};

	inline int getnamecallmethod(lua_State* LS) {
		auto Namecall = lua_namecallatom(LS, nullptr);
		if (Namecall == nullptr)
			lua_pushnil(LS);
		else
			lua_pushstring(LS, Namecall);

		return 1;
	};

	inline int getprotos(lua_State* L) {
		luaL_checktype(L, 1, LUA_TFUNCTION);

		if (lua_iscfunction(L, 1))
			luaL_argerror(L, 1, "Lua function expected");

		lua_Debug ar;
		if (!lua_getinfo(L, -1, "f", &ar))
			luaL_error(L, "invalid level passed to getprotos");

		Closure* cl = clvalue(luaA_toobject(L, -1));
		if (cl->isC) {
			lua_pop(L, 1);
			lua_newtable(L);
			return 1;
		}
		lua_pop(L, 1);

		lua_newtable(L);
		int idx = 1;
		for (auto i = 0; i < cl->l.p->sizep; ++i) {
			const auto proto = cl->l.p->p[i];
			lua_checkstack(L, 1);

			if (proto->nups <= 0) {
				Closure* clos = luaF_newLclosure(L, NULL, cl->env, proto);
				setclvalue(L, L->top, clos);
				L->top++;
			}
			else {
				lua_pushcclosure(L, [](lua_State* L) {
					return 0;
					}, 0, 0);

			}
			lua_rawseti(L, -2, idx++);
		}

		return 1;
	}

	inline int getproto(lua_State* L) {
		if (lua_iscfunction(L, -1)) {
			luaL_argerror(L, 1, "stack points to a C closure, Lua function expected");
			return 0;
		}

		Closure* cl = nullptr;
		if (lua_isnumber(L, 1)) {
			lua_Debug ar;
			if (!lua_getinfo(L, luaL_checkinteger(L, 1), "f", &ar))
				luaL_argerror(L, 1, "level out of range");
			if (lua_iscfunction(L, -1))
				luaL_argerror(L, 1, "level points to cclosure");
			cl = (Closure*)lua_topointer(L, -1);
		}
		else if (lua_isfunction(L, 1)) {
			luaL_checktype(L, 1, LUA_TFUNCTION);
			cl = (Closure*)lua_topointer(L, 1);
			if (cl->isC)
				luaL_argerror(L, 1, "lclosure expected");
		}
		else {
			luaL_argerror(L, 1, "function or number expected");
		}

		int index = std::clamp(luaL_checkinteger(L, 2), 0, cl->l.p->sizep);
		bool active = false;
		if (!lua_isnoneornil(L, 3))
			active = luaL_checkboolean(L, 3);
		if (!active) {
			if (index == 0 && cl->l.p->sizep == 0) {
				lua_pop(L, lua_gettop(L));
				lua_pushcclosure(L, [](lua_State* L) -> int {
					return 0;
					}, 0, 0);

				return 1;
			}

			if (index < 1 || index > cl->l.p->sizep)
				luaL_error(L, "index out of range %d %d", index, cl->l.p->sizep);
			Proto* p = cl->l.p->p[index - 1];
			std::unique_ptr<TValue> function(new TValue{});
			Closure* clos = luaF_newLclosure(L, 0, cl->env, p);
			setclvalue(L, function.get(), clos);
			luaA_pushobject(L, function.get());
		}
		else {
			lua_newtable(L);

			struct Ctx {
				lua_State* L;
				int count;
				Closure* cl;
			} ctx{ L, 0, cl };

			luaM_visitgco(L, &ctx, [](void* pctx, lua_Page* page, GCObject* gco) -> bool {
				Ctx* ctx = static_cast<Ctx*>(pctx);
				if (!((gco->gch.marked ^ WHITEBITS) & otherwhite(ctx->L->global)))
					return false;

				uint8_t tt = gco->gch.tt;
				if (tt == LUA_TFUNCTION) {
					Closure* cl = (Closure*)gco;
					if (!cl->isC && cl->l.p == ctx->cl->l.p->p[ctx->count]) {
						setclvalue(ctx->L, ctx->L->top, cl);
						ctx->L->top++;
						lua_rawseti(ctx->L, -2, ++ctx->count);
					}
				}
				return false;
				});
		}
		return 1;
	}

	inline int getinfo(lua_State* L) {
		if (lua_isfunction(L, 1) == false && lua_isnumber(L, 1) == false) {
			luaL_argerror(L, 1, "function or number expected");
			return 0;
		}

		intptr_t level{};
		if (lua_isfunction(L, 1))
			level = -lua_gettop(L);

		lua_Debug ar;
		if (!lua_getinfo(L, level, "sluanf", &ar))
			luaL_argerror(L, 1, "invalid level");

		lua_newtable(L);

		lua_pushvalue(L, 1);
		lua_setfield(L, -2, "func");

		lua_pushinteger(L, ar.nupvals);
		lua_setfield(L, -2, "nups");

		lua_pushstring(L, ar.source);
		lua_setfield(L, -2, "source");

		lua_pushstring(L, ar.short_src);
		lua_setfield(L, -2, "short_src");

		lua_pushinteger(L, ar.currentline);
		lua_setfield(L, -2, "currentline");

		lua_pushstring(L, ar.what);
		lua_setfield(L, -2, "what");

		lua_pushinteger(L, ar.linedefined);
		lua_setfield(L, -2, "linedefined");

		lua_pushinteger(L, ar.isvararg);
		lua_setfield(L, -2, "is_vararg");

		lua_pushinteger(L, ar.nparams);
		lua_setfield(L, -2, "numparams");

		lua_pushstring(L, ar.name);
		lua_setfield(L, -2, "name");

		if (lua_isfunction(L, 1) && lua_isLfunction(L, 1)) {
			Closure* cl = clvalue(luaA_toobject(L, 1));

			lua_pushinteger(L, cl->l.p->sizep);
			lua_setfield(L, -2, "sizep");
		}

		return 1;
	}
	inline int getconstant(lua_State* L) {
		if (lua_isfunction(L, 1) == false && lua_isnumber(L, 1) == false) {
			luaL_argerror(L, 1, "function or number expected");
			return 0;
		}

		const int index = luaL_checkinteger(L, 2);

		if (lua_isnumber(L, 1)) {
			lua_Debug ar;

			if (!lua_getinfo(L, (int)lua_tonumber(L, 1), "f", &ar)) {
				luaL_error(L, "level out of range");
				return 0;
			}

			if (lua_iscfunction(L, -1)) {
				luaL_argerror(L, 1, "stack points to a C closure, Lua function expected");
				return 0;
			}
		}
		else {
			lua_pushvalue(L, 1);

			if (lua_iscfunction(L, -1)) {
				luaL_argerror(L, 1, "Lua function expected");
				return 0;
			}
		}

		Closure* cl = (Closure*)lua_topointer(L, -1);
		Proto* p = cl->l.p;
		TValue* k = p->k;

		if (!index) {
			luaL_argerror(L, 1, "constant index starts at 1");
			return 0;
		}

		if (index > p->sizek) {
			lua_pushnil(L);
			return 1;
		}

		TValue* tval = &(k[index - 1]);

		if (tval->tt == LUA_TFUNCTION) {
			TValue* i_o = (L->top);
			setnilvalue(i_o);
			L->top++;
		}
		else {
			TValue* i_o = (L->top);
			i_o->value = tval->value;
			i_o->tt = tval->tt;
			L->top++;
		}

		return 1;
	}

	inline int getconstants(lua_State* L) {
		if (lua_isfunction(L, 1) == false && lua_isnumber(L, 1) == false) {
			luaL_argerror(L, 1, "function or number expected");
			return 0;
		}

		if (lua_isnumber(L, 1)) {
			lua_Debug ar;

			if (!lua_getinfo(L, (int)lua_tonumber(L, 1), "f", &ar)) {
				luaL_error(L, "level out of range");
				return 0;
			}

			if (lua_iscfunction(L, -1)) {
				luaL_argerror(L, 1, "stack points to a C closure, Lua function expected");
				return 0;
			}
		}
		else {
			lua_pushvalue(L, 1);

			if (lua_iscfunction(L, -1)) {
				luaL_argerror(L, 1, "Lua function expected");
				return 0;
			}
		}

		Closure* cl = (Closure*)lua_topointer(L, -1);
		Proto* p = cl->l.p;
		TValue* k = p->k;

		lua_newtable(L);

		for (int i = 0; i < p->sizek; i++) {
			TValue* tval = &(k[i]);

			if (tval->tt == LUA_TFUNCTION) {
				TValue* i_o = (L->top);
				setnilvalue(i_o);
				L->top++;
			}
			else {
				TValue* i_o = (L->top);
				i_o->value = tval->value;
				i_o->tt = tval->tt;
				L->top++;
			}

			lua_rawseti(L, -2, (i + 1));
		}

		return 1;
	}


	inline int getrenv(lua_State* L) {
		const auto RobloxState = L->global->mainthread;

		if (!RobloxState->isactive)
			luaC_threadbarrier(RobloxState);

		lua_pushvalue(RobloxState, LUA_GLOBALSINDEX);
		lua_xmove(RobloxState, L, 1);

		lua_normalisestack(L, 0);
		lua_preparepushcollectable(L, 2);
		lua_createtable(L, 2, 2);
		lua_rawgeti(L, LUA_REGISTRYINDEX, 2);
		lua_setfield(L, -2, "_G");
		lua_rawgeti(L, LUA_REGISTRYINDEX, 4);
		lua_setfield(L, -2, "shared");

		return 1;
	}


	inline int firetouchinterest(lua_State* LS) {
		luaL_checktype(LS, 1, LUA_TUSERDATA);
		luaL_checktype(LS, 2, LUA_TUSERDATA);
		int Toggle = lua_tonumber(LS, 3);

		uintptr_t BasePart = *reinterpret_cast<uintptr_t*>(lua_touserdata(LS, 1));
		if (!BasePart)
			luaL_argerror(LS, 1, "Invalid basepart");

		uintptr_t BasePartTouch = *reinterpret_cast<uintptr_t*>(lua_touserdata(LS, 2));
		if (!BasePartTouch)
			luaL_argerror(LS, 2, "Invalid basepart");

		uintptr_t Touch1 = *reinterpret_cast<uintptr_t*>(BasePart + 0x178LL);
		if (!Touch1)
			luaL_argerror(LS, 1, "Error getting primitive touch");

		uintptr_t Touch2 = *reinterpret_cast<uintptr_t*>(BasePartTouch + 0x178LL);
		if (!Touch2)
			luaL_argerror(LS, 2, "Error getting primitive touch");

		uintptr_t Overlap = *reinterpret_cast<uintptr_t*>(Touch1 + 0x1d0);
		if (!Overlap)
			luaL_argerror(LS, 1, "Error getting overlap");

		RBX::FireTouchInterest(Overlap, Touch1, Touch2, Toggle, true);
	};

	inline int lz4compress(lua_State* LS) {
		//("lz4compress");
		luaL_checktype(LS, 1, LUA_TSTRING);

		const char* data = lua_tostring(LS, 1);
		int nMaxCompressedSize = LZ4_compressBound(strlen(data));
		char* out_buffer = new char[nMaxCompressedSize];

		LZ4_compress(data, out_buffer, strlen(data));
		lua_pushlstring(LS, out_buffer, nMaxCompressedSize);
		return 1;
	};

	inline int lz4decompress(lua_State* LS) {
		//("lz4decompress");

		luaL_checktype(LS, 1, LUA_TSTRING);
		luaL_checktype(LS, 2, LUA_TNUMBER);

		const char* data = lua_tostring(LS, 1);
		int data_size = lua_tointeger(LS, 2);

		char* pszUnCompressedFile = new char[data_size];

		LZ4_uncompress(data, pszUnCompressedFile, data_size);
		lua_pushlstring(LS, pszUnCompressedFile, data_size);
		return 1;
	};

	inline int fireproximityprompt(lua_State* LS) {
		//("fireproximityprompt");

		luaL_checktype(LS, 1, LUA_TUSERDATA);

		uintptr_t ProximityPrompt = *(uintptr_t*)(lua_topointer(LS, 1));
		if (!ProximityPrompt)
			luaL_argerror(LS, 1, "Invalid proximity prompt!");

		RBX::FireProximityPrompt(ProximityPrompt);
		return 0;
	};
	static std::mutex Tpmutext;
	inline int queue_on_teleport(lua_State* LS) {
		const auto script = luaL_checkstring(LS, 1);

		std::unique_lock<std::mutex> locker{ Tpmutext };
		return 0;
	};
	inline int gethui(lua_State* LS)
	{
		lua_getglobal(LS, "__hiddeninterface");

		return 1;
	};


	inline int getinstances(lua_State* LS) {
		lua_pop(LS, lua_gettop(LS));

		HelpFuncs::GetEveryInstance(LS);

		if (!lua_istable(LS, -1)) { lua_pop(LS, 1); lua_pushnil(LS); return 1; };

		lua_newtable(LS);

		int index = 0;

		lua_pushnil(LS);
		while (lua_next(LS, -3) != 0) {

			if (!lua_isnil(LS, -1)) {
				lua_getglobal(LS, "typeof");
				lua_pushvalue(LS, -2);
				lua_pcall(LS, 1, 1, 0);

				std::string type = lua_tostring(LS, -1);
				lua_pop(LS, 1);

				if (type == "Instance") {
					lua_pushinteger(LS, ++index);

					lua_pushvalue(LS, -2);
					lua_settable(LS, -5);
				}
			}

			lua_pop(LS, 1);
		}

		lua_remove(LS, -2);

		return 1;
	};

	inline int getnilinstances(lua_State* LS)
	{
		//("getnilinstances");

		lua_pop(LS, lua_gettop(LS));

		HelpFuncs::GetEveryInstance(LS);

		if (!lua_istable(LS, -1)) { lua_pop(LS, 1); lua_pushnil(LS); return 1; };

		lua_newtable(LS);

		int index = 0;

		lua_pushnil(LS);
		while (lua_next(LS, -3) != 0) {

			if (!lua_isnil(LS, -1)) {
				lua_getglobal(LS, "typeof");
				lua_pushvalue(LS, -2);
				lua_pcall(LS, 1, 1, 0);

				std::string type = lua_tostring(LS, -1);
				lua_pop(LS, 1);

				if (type == "Instance") {
					lua_getfield(LS, -1, "Parent");
					int parentType = lua_type(LS, -1);
					lua_pop(LS, 1);

					if (parentType == LUA_TNIL) {
						lua_pushinteger(LS, ++index);

						lua_pushvalue(LS, -2);
						lua_settable(LS, -5);
					}
				}
			}

			lua_pop(LS, 1);
		}

		lua_remove(LS, -2);

		return 1;
	};

	inline int getscripts(lua_State* L) {
		//("getscripts");

		lua_pop(L, lua_gettop(L));

		HelpFuncs::GetEveryInstance(L);

		if (!lua_istable(L, -1)) {
			lua_pop(L, 1);
			lua_pushnil(L);
			return 1;
		}

		lua_newtable(L);
		int resultIndex = lua_gettop(L);

		int index = 0;

		lua_pushnil(L);
		while (lua_next(L, -3) != 0) {
			if (!lua_isnil(L, -1)) {
				lua_getfield(L, -1, "ClassName");

				if (lua_isstring(L, -1)) {
					std::string type = lua_tostring(L, -1);
					if (type == "LocalScript" || type == "ModuleScript" || type == "Script") {
						lua_pushinteger(L, ++index);
						lua_pushvalue(L, -3);
						lua_settable(L, resultIndex);
					}
				}

				lua_pop(L, 1);
			}

			lua_pop(L, 1);
		}

		lua_remove(L, -2);

		return 1;
	}

	inline int getrunningscripts(lua_State* LS) {
		//("getrunningscripts");

		lua_newtable(LS);

		typedef struct {
			lua_State* State;
			int itemsFound;
			std::map< uintptr_t, bool > map;
		} GCOContext;

		auto gcCtx = GCOContext{ LS, 0 };

		const auto ullOldThreshold = LS->global->GCthreshold;
		LS->global->GCthreshold = SIZE_MAX;

		luaM_visitgco(LS, &gcCtx, [](void* ctx, lua_Page* pPage, GCObject* pGcObj) -> bool {
			const auto pCtx = static_cast<GCOContext*>(ctx);
			const auto ctxL = pCtx->State;

			if (isdead(ctxL->global, pGcObj))
				return false;

			if (const auto gcObjType = pGcObj->gch.tt;
				gcObjType == LUA_TFUNCTION) {
				ctxL->top->value.gc = pGcObj;
				ctxL->top->tt = gcObjType;
				ctxL->top++;

				lua_getfenv(ctxL, -1);

				if (!lua_isnil(ctxL, -1)) {
					lua_getfield(ctxL, -1, "script");

					if (!lua_isnil(ctxL, -1)) {
						uintptr_t Script = *(uintptr_t*)lua_touserdata(ctxL, -1);

						std::string ClassName = **(std::string**)(*(uintptr_t*)(Script + Offsets::Properties::ClassDescriptor) + Offsets::Properties::ClassName);

						if (pCtx->map.find(Script) == pCtx->map.end() && (ClassName == "LocalScript" || ClassName == "ModuleScript" || ClassName == "Script")) {
							pCtx->map.insert({ Script, true });
							lua_rawseti(ctxL, -4, ++pCtx->itemsFound);
						}
						else {
							lua_pop(ctxL, 1);
						}
					}
					else {
						lua_pop(ctxL, 1);
					}
				}

				lua_pop(ctxL, 2);
			}
			return false;
			});

		LS->global->GCthreshold = ullOldThreshold;

		return 1;
	};

	inline int getloadedmodules(lua_State* LS) {
		//("getloadedmodules");

		lua_pop(LS, lua_gettop(LS));

		getrunningscripts(LS);

		if (!lua_istable(LS, -1)) {
			lua_pop(LS, 1);
			lua_pushnil(LS);
			return 1;
		}

		lua_newtable(LS);
		int resultIndex = lua_gettop(LS);

		int index = 0;

		lua_pushnil(LS);
		while (lua_next(LS, -3) != 0) {
			if (!lua_isnil(LS, -1)) {
				lua_getfield(LS, -1, "ClassName");

				if (lua_isstring(LS, -1)) {
					std::string type = lua_tostring(LS, -1);
					if (type == "ModuleScript") {
						lua_pushinteger(LS, ++index);
						lua_pushvalue(LS, -3);
						lua_settable(LS, resultIndex);
					}
				}

				lua_pop(LS, 1);
			}

			lua_pop(LS, 1);
		}

		lua_remove(LS, -2);

		return 1;
	};

	inline int getscriptbytecode(lua_State* LS) {
		//("getscriptbytecode");

		luaL_checktype(LS, 1, LUA_TUSERDATA);

		std::string Bytecode = HelpFuncs::RequestBytecode(*(uintptr_t*)lua_topointer(LS, 1), true);

		if (Bytecode != "Nil")
		{
			lua_pushlstring(LS, Bytecode.data(), Bytecode.size());
		}
		else
			lua_pushnil(LS);

		return 1;

	};

	inline int getcallingscript(lua_State* LS) {
		//("getcallingscript");

		std::uintptr_t scriptPtr = *(std::uintptr_t*)LS->userdata + 0x50;
		if (!scriptPtr)
		{
			lua_pushnil(LS);
			return 1;
		}

		RBX::PushInstance(LS, (void*)scriptPtr);
		return 1;
	};
	inline int getscripthash(lua_State* LS) {
		luaL_checktype(LS, 1, LUA_TUSERDATA);

		if (!HelpFuncs::IsClassName(LS, 1, "ModuleScript") && !HelpFuncs::IsClassName(LS, 1, "LocalScript") && !HelpFuncs::IsClassName(LS, 1, "Script"))
		{
			luaL_argerror(LS, 1, "Expected a ModuleScript or a LocalScript");
			return 0;
		}

		std::string Bytecode = HelpFuncs::RequestBytecode(*(uintptr_t*)lua_topointer(LS, 1), false);

		if (Bytecode != "Nil")
		{
			std::string hash = Crypt::HelpFunctions::hash_with_algo<CryptoPP::SHA384>(Bytecode);
			lua_pushstring(LS, hash.c_str());
		}
		else
			lua_pushnil(LS);

		return 1;
	};
	inline int getscriptclosure(lua_State* LS) {
		//("getscriptclosure");

		luaL_checktype(LS, 1, LUA_TUSERDATA);

		if (!HelpFuncs::IsClassName(LS, 1, "ModuleScript") && !HelpFuncs::IsClassName(LS, 1, "LocalScript") && !HelpFuncs::IsClassName(LS, 1, "Script"))
		{
			luaL_argerror(LS, 1, "Expected a ModuleScript or a LocalScript");
			return 0;
		}

		std::string scriptCode = HelpFuncs::RequestBytecode(*(uintptr_t*)lua_topointer(LS, 1), false);
		if (scriptCode == "Nil")
		{
			lua_pushnil(LS);
			return 1;
		}

		lua_State* L2 = lua_newthread(LS);
		luaL_sandboxthread(L2);

		TaskScheduler::SetThreadCapabilities(L2, 8, ~0ULL);

		lua_pushvalue(LS, 1);
		lua_xmove(LS, L2, 1);
		lua_setglobal(L2, "script");

		int result = RBX::LuaVM__Load(L2, &scriptCode, "", 0);
		if (result == LUA_OK) {
			Closure* cl = clvalue(luaA_toobject(L2, -1));

			if (cl) {
				Proto* p = cl->l.p;
				if (p) {
					TaskScheduler::SetProtoCapabilities(p);
				}
			}

			lua_pop(L2, lua_gettop(L2));
			lua_pop(LS, lua_gettop(LS));

			setclvalue(LS, LS->top, cl);
			incr_top(LS);

			return 1;
		}
		else
		{
			luaL_error(LS, "Error loading the script bytecode!");
		}

		lua_pushnil(LS);
		return 1;
	}


	inline int isscriptable(lua_State* LS)
	{
		//("isscriptable");

		luaL_checktype(LS, 1, LUA_TUSERDATA);
		luaL_checktype(LS, 2, LUA_TSTRING);

		uintptr_t Instance = *reinterpret_cast<uintptr_t*>(lua_touserdata(LS, 1));
		if (!Instance)
			luaL_argerror(LS, 1, "Invalid instance!");

		auto Property = lua_tostring(LS, 2);

		const auto EveryProperties = InstancesHelper::GetInstanceProperties(Instance);
		if (!EveryProperties.contains(Property))
			luaG_runerrorL(LS, "This property doesn't exist");

		const auto PropertyAddress = EveryProperties.at(Property);

		int cachedProperty = getCachedScriptableProperty(Instance, Property);
		int cachedDefaultProperty = getCachedDefultScriptableProperty(Property);

		if (cachedProperty != -1) {
			lua_pushboolean(LS, cachedProperty);
			return 1;
		}

		if (cachedDefaultProperty != -1) {
			lua_pushboolean(LS, cachedDefaultProperty);
			return 1;
		}

		lua_pushboolean(LS, InstancesHelper::luau_isscriptable(PropertyAddress));

		return 1;
	};
	inline int setscriptable(lua_State* LS)
	{
		luaL_checktype(LS, 1, LUA_TUSERDATA);
		luaL_checktype(LS, 2, LUA_TSTRING);
		luaL_checktype(LS, 3, LUA_TBOOLEAN);

		uintptr_t Instance = *reinterpret_cast<uintptr_t*>(lua_touserdata(LS, 1));
		if (!Instance)
			luaL_argerror(LS, 1, "Invalid instance!");

		auto Property = lua_tostring(LS, 2);

		bool Scriptable = lua_toboolean(LS, 3);

		const auto EveryProperties = InstancesHelper::GetInstanceProperties(Instance);
		if (!EveryProperties.contains(Property))
			luaG_runerrorL(LS, "This property doesn't exist");

		const auto PropertyAddress = EveryProperties.at(Property);

		if (!findAndUpdateScriptAbleCache(Instance, Property, Scriptable))
			script_able_cache.push_back({ Instance, Property, Scriptable });

		bool WasScriptable = InstancesHelper::luau_isscriptable(PropertyAddress);

		addDefaultPropertyState(Property, WasScriptable);

		InstancesHelper::luau_setscriptable(PropertyAddress, Scriptable);

		lua_pushboolean(LS, WasScriptable);

		return 1;
	};


	inline int getcallbackvalue(lua_State* LS) {
		HelpFuncs::IsInstance(LS, 1);
		luaL_checktype(LS, 2, LUA_TSTRING);

		const auto rawInstance = reinterpret_cast<uintptr_t>(lua_torawuserdata(LS, 1));
		int Atom;
		lua_tostringatom(LS, 2, &Atom);

		auto propertyName = reinterpret_cast<uintptr_t*>(Offsets::KTable)[Atom];
		if (propertyName == 0 || IsBadReadPtr(reinterpret_cast<void*>(propertyName), 0x10))
			luaL_argerrorL(LS, 2, "Invalid property!");

		const auto instanceClassDescriptor = *reinterpret_cast<uintptr_t*>(
			rawInstance + Offsets::Properties::ClassDescriptor);
		const auto Property = RBX::GetProperty(
			instanceClassDescriptor + Offsets::Properties::PropertyDescriptor,
			&propertyName);
		if (Property == 0 || IsBadReadPtr(reinterpret_cast<void*>(Property), 0x10))
			luaL_argerrorL(LS, 2, "Invalid property!");

		const auto callbackStructureStart = rawInstance + *reinterpret_cast<uintptr_t*>(
			*reinterpret_cast<uintptr_t*>(Property) + 0x80);
		const auto hasCallback = *reinterpret_cast<uintptr_t*>(callbackStructureStart + 0x38);
		if (hasCallback == 0) {
			lua_pushnil(LS);
			return 1;
		}

		const auto callbackStructure = *reinterpret_cast<uintptr_t*>(callbackStructureStart + 0x18);
		if (callbackStructure == 0) {
			lua_pushnil(LS);
			return 1;
		}

		const auto ObjectRefs = *reinterpret_cast<uintptr_t*>(callbackStructure + 0x38);
		if (ObjectRefs == 0) {
			lua_pushnil(LS);
			return 1;
		}

		const auto ObjectRef = *reinterpret_cast<uintptr_t*>(ObjectRefs + 0x28);
		const auto RefId = *reinterpret_cast<int*>(ObjectRef + 0x14);

		lua_getref(LS, RefId);
		return 1;
		return 0;
	}

	inline int fireclickdetector(lua_State* L) {
		luaL_checktype(L, 1, LUA_TUSERDATA);

		std::string clickOption = lua_isstring(L, 3) ? lua_tostring(L, 3) : "";

		if (strcmp(luaL_typename(L, 1), "Instance") != 0)
		{
			luaL_typeerror(L, 1, "Instance");
			return 0;
		}

		const auto clickDetector = *reinterpret_cast<uintptr_t*>(lua_touserdata(L, 1));

		float distance = 0.0;

		if (lua_isnumber(L, 2))
			distance = (float)lua_tonumber(L, 2);

		lua_getglobal(L, "game");
		lua_getfield(L, -1, "GetService");
		lua_insert(L, -2);
		lua_pushstring(L, "Players");
		lua_pcall(L, 2, 1, 0);

		lua_getfield(L, -1, "LocalPlayer");

		const auto localPlayer = *reinterpret_cast<uintptr_t*>(lua_touserdata(L, -1));

		std::transform(clickOption.begin(), clickOption.end(), clickOption.begin(), ::tolower);

		if (clickOption == "rightmouseclick")
			RBX::FireRightMouseClick(clickDetector, distance, localPlayer);
		else if (clickOption == "mousehoverenter")
			RBX::FireMouseHoverEnter(clickDetector, localPlayer);
		else if (clickOption == "mousehoverleave")
			RBX::FireMouseHoverLeave(clickDetector, localPlayer);
		else
			RBX::FireMouseClick(clickDetector, distance, localPlayer);
		return 0;
	}

	inline int islclosure(lua_State* L) {
		luaL_checktype(L, 1, LUA_TFUNCTION);

		Closure* closure = clvalue(luaA_toobject(L, 1));

		lua_pushboolean(L, !closure->isC);

		return 1;
	}
	inline int iscclosure(lua_State* L) {
		luaL_checktype(L, 1, LUA_TFUNCTION);

		Closure* closure = clvalue(luaA_toobject(L, 1));

		lua_pushboolean(L, closure->isC);

		return 1;
	}

	inline int setclipboard(lua_State* L) {
		luaL_checktype(L, 1, LUA_TSTRING);

		std::string text = lua_tostring(L, 1);

		if (OpenClipboard(nullptr)) {
			EmptyClipboard();
			HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
			if (hMem) {
				void* memPtr = GlobalLock(hMem);
				if (memPtr) {
					memcpy(memPtr, text.c_str(), text.size() + 1);
					GlobalUnlock(hMem);
					SetClipboardData(CF_TEXT, hMem);
				}
			}
			CloseClipboard();
		}

		return 0;
	}

	inline int handler(lua_State* L) {
		const auto arg_count = lua_gettop(L);
		const auto closure = g_newcclosure_cache.get(clvalue(L->ci->func));

		if (!closure)
			luaL_error(L, "Failed to find closure");

		setclvalue(L, L->top, *closure);
		L->top++;

		lua_insert(L, 1);

		StkId func = L->base;
		L->ci->flags |= LUA_CALLINFO_HANDLE;

		L->baseCcalls++;
		int status = luaD_pcall(L, handler_run, func, savestack(L, func), 0);
		L->baseCcalls--;

		if (status == LUA_ERRRUN) {
			std::string regexed_error = lua_tostring(L, -1);
			lua_pop(L, 1);

			lua_pushlstring(L, regexed_error.c_str(), regexed_error.size());
			lua_error(L);
			return 0;
		}

		expandstacklimit(L, L->top);

		if (status == 0 && (L->status == LUA_YIELD || L->status == LUA_BREAK))
			return -1;

		return lua_gettop(L);
	};

	inline int wrapclosure(lua_State* L, int index) {
		luaL_checktype(L, index, LUA_TFUNCTION);

		lua_ref(L, index);
		lua_pushcclosurek(L, handler, nullptr, 0, handler_continuation);
		lua_ref(L, -1);

		g_newcclosure_cache.add(clvalue(luaA_toobject(L, -1)), clvalue(luaA_toobject(L, index)));

		return 1;
	};
	static std::unordered_map<Closure*, Closure*> original_functions;
	inline int hookfunction(lua_State* L) {
		if (!lua_isfunction(L, 1) || !lua_isfunction(L, 2)) {
			lua_pushstring(L, "Both arguments must be functions");
			lua_error(L);
			return 0;
		}

		// Get closures
		Closure* Function = clvalue(luaA_toobject(L, 1));
		Closure* Hook = clvalue(luaA_toobject(L, 2));

		if (original_functions.count(Function) == 0)
		{
			lua_clonefunction(L, 1);
			original_functions[Function] = lua_toclosure(L, -1);
			lua_pop(L, 1);
		}

		if (!Function || !Hook) {
			lua_pushstring(L, "Failed to find closure");
			lua_error(L);
			return 0;
		}

		// Push original function to return it later
		lua_pushvalue(L, 1);

		if (Function->isC) {
			if (Hook->isC) {
				// C->C, C->NC, NC->C, NC->NC
				//RBX::Print(1, "C->C, C->NC, NC->C, NC->NC");

				// Store original C function
				lua_CFunction Func1 = Hook->c.f;

				// Clone the original function to return it
				lua_clonecfunction(L, 1);
				lua_ref(L, -1);

				// Copy upvalues from hook to original function
				for (int i = 0; i < Hook->nupvalues; i++) {
					auto OldTValue = &Function->c.upvals[i];
					auto HookTValue = &Hook->c.upvals[i];
					OldTValue->value = HookTValue->value;
					OldTValue->tt = HookTValue->tt;
				}

				// Update cache if needed
				auto closureOpt = g_newcclosure_cache.get(Function);
				if (closureOpt.has_value()) {
					Closure* cachedClosure = closureOpt.value();
					g_newcclosure_cache.remove(Function);
					g_newcclosure_cache.add(Function, Hook);

					// Get the cloned function closure
					Closure* clonedClosure = clvalue(luaA_toobject(L, -1));
					if (clonedClosure) {
						g_newcclosure_cache.add(clonedClosure, cachedClosure);
					}
				}

				// Update function properties
				Function->nupvalues = Hook->nupvalues;
				Function->c.f = Func1;

				return 1;
			}
			else {
				// C->L, NC->L
				//RBX::Print(1, "C->L, NC->L");

				// Wrap the Lua closure to be called from C
				wrapclosure(L, 2);
				lua_ref(L, -1);

				// Clone the original function to return it
				lua_clonecfunction(L, 1);
				lua_ref(L, -1);

				// Update cache
				g_newcclosure_cache.add(Function, Hook);

				// Set handler functions
				Function->c.f = reinterpret_cast<lua_CFunction>(handler);
				Function->c.cont = reinterpret_cast<lua_Continuation>(handler_continuation);

				return 1;
			}
		}
		else {
			// Function is a Lua closure
			if (Hook->isC) {
				// L->C: convert C function to Lua function
				lua_newtable(L);
				lua_newtable(L);
				lua_pushvalue(L, LUA_GLOBALSINDEX);
				lua_setfield(L, -2, "__index");
				lua_setreadonly(L, -1, true);
				lua_setmetatable(L, -2);

				// Store the C function in the environment
				lua_pushvalue(L, 2);
				lua_setfield(L, -2, "cFuncCall");

				// Compile a Lua function that calls the C function
				std::string bytecode = Execution->CompileScript("return cFuncCall(...)", LUAVM_LOAD);
				int loadResult = RBX::LuaVM__Load(L, &bytecode, "=", -1);

				if (loadResult != 0) {
					lua_pushstring(L, "Failed to compile wrapper for C function");
					lua_error(L);
					return 0;
				}

				// Update Hook to point to the new Lua closure
				Hook = clvalue(luaA_toobject(L, -1));

				if (!Hook) {
					lua_pushstring(L, "Failed to convert C function to Lua function");
					lua_error(L);
					return 0;
				}
			}

			// L->C, L->NC, L->L
			//RBX::Print(1, "L->C, L->NC, L->L");

			// Clone the original function to return it
			lua_clonefunction(L, 1);

			// Get the prototype from the hook
			Proto* newProto = Hook->l.p;

			// Update function properties
			Function->env = Hook->env;
			Function->stacksize = Hook->stacksize;
			Function->preload = Hook->preload;

			// Copy upvalues
			for (int i = 0; i < Hook->nupvalues; ++i) {
				setobj2n(L, &Function->l.uprefs[i], &Hook->l.uprefs[i]);
			}

			Function->nupvalues = Hook->nupvalues;
			Function->l.p = newProto;

			return 1;
		}
	}

	__forceinline static int restorefunction(lua_State* L) {
		luaL_checktype(L, 1, LUA_TFUNCTION);
		auto current = lua_toclosure(L, 1);
		auto it = original_functions.find(current);

		if (it == original_functions.end()) {
			luaL_error(L, "Function was not previously hooked");
			return 0;
		}

		auto original = it->second;

		if (current->isC) {
			current->c.f = original->c.f;
			current->c.cont = original->c.cont;
			current->nupvalues = original->nupvalues;

			for (int i = 0; i < original->nupvalues; i++) {
				current->c.upvals[i] = original->c.upvals[i];
			}

			auto closureOpt = g_newcclosure_cache.get(current);
			if (closureOpt.has_value()) {
				g_newcclosure_cache.remove(current);
			}
		}
		else {
			current->l.p = original->l.p;
			current->env = original->env;
			current->stacksize = original->stacksize;
			current->preload = original->preload;
			current->nupvalues = original->nupvalues;

			for (int i = 0; i < original->nupvalues; i++) {
				setobj2n(L, &current->l.uprefs[i], &original->l.uprefs[i]);
			}
		}

		original_functions.erase(it);
		lua_pushboolean(L, 1);
		return 1;
	}


	inline int checkcaller(lua_State* L) {
		lua_pushboolean(L, L->userdata->Script.expired());

		return 1;
	}
	inline int clonefunction(lua_State* L) {
		luaL_checktype(L, 1, LUA_TFUNCTION);

		Closure* toClone = clvalue(luaA_toobject(L, 1));

		if (toClone->isC)
			lua_clonecfunction(L, 1);
		else
			lua_clonefunction(L, 1);

		Closure* cloned = clvalue(luaA_toobject(L, -1));

		return 1;
	}



	inline int getrawmetatable(lua_State* LS) {
		luaL_checkany(LS, 1);

		if (!lua_getmetatable(LS, 1))
			lua_pushnil(LS);

		return 1;
	};

	inline int setrawmetatable(lua_State* LS) {
		luaL_argexpected(LS, lua_istable(LS, 1) || lua_islightuserdata(LS, 1) || lua_isuserdata(LS, 1) || lua_isbuffer(LS, 1) || lua_isvector(LS, 1), 1, "Expected a table or an userdata or a buffer or a vector");

		luaL_argexpected(LS, lua_istable(LS, 2) || lua_isnil(LS, 2), 2, "Expected table or nil");

		const bool OldState = lua_getreadonly(LS, 1);

		lua_setreadonly(LS, 1, false);

		lua_setmetatable(LS, 1);

		lua_setreadonly(LS, 1, OldState);

		lua_ref(LS, 1);

		return 1;
	};
	inline int isreadonly(lua_State* LS) {
		//("isreadonly");

		lua_pushboolean(LS, lua_getreadonly(LS, 1));
		return 1;
	};

	inline int setreadonly(lua_State* LS) {
		//("setreadonly");

		luaL_checktype(LS, 1, LUA_TTABLE);
		luaL_checktype(LS, 2, LUA_TBOOLEAN);

		lua_setreadonly(LS, 1, lua_toboolean(LS, 2));

		return 0;
	};

	inline int getreg(lua_State* LS) {
		//("getreg");

		lua_pushvalue(LS, LUA_REGISTRYINDEX);
		return 1;
	};

	__forceinline void convert_level_or_function_to_closure(lua_State* L, const char* cFunctionErrorMessage,
		const bool shouldErrorOnCFunction = true) {
		luaL_checkany(L, 1);

		if (lua_isnumber(L, 1)) {
			lua_Debug debugInfo{};
			const auto level = lua_tointeger(L, 1);

			if (level < 0 || level > 255)
				luaL_argerrorL(L, 1, "level out of bounds");

			if (!lua_getinfo(L, level, "f", &debugInfo))
				luaL_argerrorL(L, 1, "invalid level");
		}
		else if (lua_isfunction(L, 1)) {
			lua_pushvalue(L, 1);
		}
		else {
			luaL_argerrorL(L, 1, "level or function expected");
		}

		if (!lua_isfunction(L, -1))
			luaL_argerrorL(L, 1, "There isn't function on stack");

		if (shouldErrorOnCFunction && lua_iscfunction(L, -1))
			luaL_argerrorL(L, 1, cFunctionErrorMessage);
	}

	inline int setconstant(lua_State* L) {
		//("debug.setconstant");

		luaL_trimstack(L, 3);
		luaL_checktype(L, 2, LUA_TNUMBER);
		luaL_argexpected(L, lua_isnumber(L, 3) || lua_isboolean(L, 3) || lua_isstring(L, 3), 3,
			"number or boolean or string");
		convert_level_or_function_to_closure(L, "Cannot set constants on a C closure");

		const auto constantIndex = lua_tointeger(L, 2);
		const auto closure = lua_toclosure(L, -1);

		luaL_argcheck(L, constantIndex > 0, 2, "index cannot be negative");
		luaL_argcheck(L, constantIndex <= closure->l.p->sizek, 3, "index out of range");

		setobj(L, &closure->l.p->k[constantIndex - 1], index2addr(L, 3))

			return 0;
	}



	inline int getupvalues(lua_State* L) {
		if (lua_isfunction(L, 1) == false && lua_isnumber(L, 1) == false) {
			luaL_argerror(L, 1, "function or number expected");
			return 0;
		}

		if (lua_isnumber(L, 1)) {
			lua_Debug ar;

			if (!lua_getinfo(L, (int)lua_tonumber(L, 1), "f", &ar)) {
				luaL_error(L, "level out of range");
				return 0;
			}
		}
		else {
			lua_pushvalue(L, 1);
		}

		Closure* closure = (Closure*)lua_topointer(L, -1);
		TValue* upvalue_table = (TValue*)nullptr;

		lua_newtable(L);

		if (!closure->isC)
			upvalue_table = closure->l.uprefs;
		else if (closure->isC)
			upvalue_table = closure->c.upvals;

		for (int i = 0; i < closure->nupvalues; i++) {
			TValue* upval = (&upvalue_table[i]);
			TValue* top = L->top;

			top->value = upval->value;
			top->tt = upval->tt;
			L->top++;

			lua_rawseti(L, -2, (i + 1));
		}

		return 1;
	}

	inline int debug_setupvalue(lua_State* L) {
		//("debug.setupvalue");

		luaL_trimstack(L, 3);
		luaL_checktype(L, 2, LUA_TNUMBER);
		luaL_checkany(L, 3);
		convert_level_or_function_to_closure(L, "Cannot set upvalue on C Closure", true);

		const auto closure = lua_toclosure(L, -1);
		const auto upvalueIndex = lua_tointeger(L, 2);
		const auto objToSet = index2addr(L, 3);

		luaL_argcheck(L, upvalueIndex > 0, 2, "index cannot be negative");
		luaL_argcheck(L, upvalueIndex <= closure->nupvalues, 2, "index out of range");

		setobj(L, &closure->l.uprefs[upvalueIndex - 1], objToSet);
		return 0;
	}




	inline int setstack(lua_State* L) {
		luaL_checktype(L, 1, LUA_TNUMBER);
		luaL_checktype(L, 2, LUA_TNUMBER);
		luaL_checkany(L, 3);

		const auto level = lua_tointeger(L, 1);
		const auto index = lua_tointeger(L, 2);

		if (level >= L->ci - L->base_ci || level < 0) {
			luaL_argerror(L, 1, "level out of range");
		}

		const auto frame = reinterpret_cast<CallInfo*>(L->ci - level);
		const auto top = (frame->top - frame->base);

		if (clvalue(frame->func)->isC) {
			luaL_argerror(L, 1, "level points to a cclosure, lclosure expected");
		}

		if (index < 1 || index > top) {
			luaL_argerror(L, 2, "stack index out of range");
		}

		setobj2s(L, &frame->base[index - 1], luaA_toobject(L, 3));
		return 0;
	}

	inline int getstack(lua_State* L) {
		luaL_checktype(L, 1, LUA_TNUMBER);

		const auto level = lua_tointeger(L, 1);
		const auto index = luaL_optinteger(L, 2, -1);

		if (level >= L->ci - L->base_ci || level < 0) {
			luaL_argerror(L, 1, "level out of range");
		}

		const auto frame = reinterpret_cast<CallInfo*>(L->ci - level);
		const auto top = (frame->top - frame->base);

		if (clvalue(frame->func)->isC) {
			luaL_argerror(L, 1, "level points to a cclosure, lclosure expected");
		}

		if (index == -1) {
			lua_newtable(L);

			for (int i = 0; i < top; i++) {
				setobj2s(L, L->top, &frame->base[i]);
				L->top++;

				lua_rawseti(L, -2, i + 1);
			}
		}
		else {
			if (index < 1 || index > top) {
				luaL_argerror(L, 2, "stack index out of range");
			}

			setobj2s(L, L->top, &frame->base[index - 1]);
			L->top++;
		}
		return 1;
	}

	inline int getupvalue(lua_State* L) {
		if (lua_isfunction(L, 1) == false && lua_isnumber(L, 1) == false) {
			luaL_argerror(L, 1, "function or number expected");
			return 0;
		}

		if (lua_isnumber(L, 1)) {
			lua_Debug ar;

			if (!lua_getinfo(L, (int)lua_tonumber(L, 1), "f", &ar)) {
				luaL_error(L, "level out of range");
				return 0;
			}
		}
		else
			lua_pushvalue(L, 1);

		const int index = luaL_checkinteger(L, 2);

		Closure* closure = (Closure*)lua_topointer(L, -1);
		TValue* upvalue_table = (TValue*)nullptr;

		if (!closure->isC)
			upvalue_table = closure->l.uprefs;
		else if (closure->isC)
			upvalue_table = closure->c.upvals;

		if (!index) {
			luaL_argerror(L, 1, "upvalue index starts at 1");
			return 0;
		}

		if (index > closure->nupvalues) {
			luaL_argerror(L, 1, "upvalue index is out of range");
			return 0;
		}

		TValue* upval = (&upvalue_table[index - 1]);
		TValue* top = L->top;

		top->value = upval->value;
		top->tt = upval->tt;
		L->top++;

		return 1;
	}

	//// !!!!!!!!!!!!!!!!!!!! 
	inline int loadstring(lua_State* L) {
		luaL_checktype(L, 1, LUA_TSTRING);

		const std::string source = lua_tostring(L, 1);
		const std::string chunkname = luaL_optstring(L, 2, "=");

		std::string script = Execution->CompileScript(source, LUAVM_LOAD);

		if (script[0] == '\0' || script.empty()) {
			lua_pushnil(L);
			lua_pushstring(L, "Failed to compile script");
			return 2;
		}

		int result = RBX::LuaVM__Load(L, &script, chunkname.data(), 0);
		if (result != LUA_OK) {
			std::string Error = luaL_checklstring(L, -1, nullptr);
			lua_pop(L, 1);

			lua_pushnil(L);
			lua_pushstring(L, Error.data());

			return 2;
		}

		Closure* closure = clvalue(luaA_toobject(L, -1));

		TaskScheduler::SetProtoCapabilities(closure->l.p);

		return 1;
	}

	inline int gettenv(lua_State* LS) {
		luaL_checktype(LS, 1, LUA_TTHREAD);
		lua_State* ls = (lua_State*)lua_topointer(LS, 1);
		LuaTable* tab = hvalue(luaA_toobject(ls, LUA_GLOBALSINDEX));
#define isdead(g, obj) ((obj)->gch.marked & (g)->currentwhite) == 0
		sethvalue(LS, LS->top, tab);

		LS->top++;

		return 1;
	};
	inline int identifyexecutor(lua_State* L) {
		//("identifyexecutor");
		lua_pushstring(L, "Cloudy");
		lua_pushstring(L, "5.0");
		return 1;
	}
	inline int isrbxactive(lua_State* L) {
		lua_pushboolean(L, (GetForegroundWindow() == FindWindowA(NULL, "Roblox")));
		return 1;
	}
	inline int getfenv(lua_State* L) {
		luaL_checktype(L, 1, LUA_TFUNCTION);
		lua_pushvalue(L, 1);
		lua_getfenv(L, -1);
		return 1;
	}
	inline int invalidate(lua_State* LS) {
		//("invalidate");

		luaL_checktype(LS, 1, LUA_TUSERDATA);

		HelpFuncs::IsInstance(LS, 1);

		const auto Instance = *static_cast<void**>(lua_touserdata(LS, 1));

		lua_pushlightuserdata(LS, (void*)Offsets::Functions::PushInstance);
		lua_gettable(LS, LUA_REGISTRYINDEX);

		lua_pushlightuserdata(LS, reinterpret_cast<void*>(Instance));
		lua_pushnil(LS);
		lua_settable(LS, -3);

		return 0;
	};
	inline int replace(lua_State* LS) {
		//("replace");

		luaL_checktype(LS, 1, LUA_TUSERDATA);
		luaL_checktype(LS, 2, LUA_TUSERDATA);

		HelpFuncs::IsInstance(LS, 1);
		HelpFuncs::IsInstance(LS, 2);

		const auto Instance = *reinterpret_cast<uintptr_t*>(lua_touserdata(LS, 1));

		lua_pushlightuserdata(LS, (void*)Offsets::Functions::PushInstance);
		lua_gettable(LS, LUA_REGISTRYINDEX);

		lua_pushlightuserdata(LS, (void*)Instance);
		lua_pushvalue(LS, 2);
		lua_settable(LS, -3);
		return 0;
	}
	inline int iscached(lua_State* LS) {
		//("iscached");

		luaL_checktype(LS, 1, LUA_TUSERDATA);

		HelpFuncs::IsInstance(LS, 1);
		const auto Instance = *static_cast<void**>(lua_touserdata(LS, 1));

		lua_pushlightuserdata(LS, (void*)Offsets::Functions::PushInstance);
		lua_gettable(LS, LUA_REGISTRYINDEX);

		lua_pushlightuserdata(LS, Instance);
		lua_gettable(LS, -2);

		lua_pushboolean(LS, !lua_isnil(LS, -1));
		return 1;
	}
	inline int cloneref(lua_State* LS) {
		//("cloneref");

		luaL_checktype(LS, 1, LUA_TUSERDATA);

		HelpFuncs::IsInstance(LS, 1);

		const auto OldUserdata = lua_touserdata(LS, 1);

		const auto NewUserdata = *reinterpret_cast<uintptr_t*>(OldUserdata);

		lua_pushlightuserdata(LS, (void*)Offsets::Functions::PushInstance);

		lua_rawget(LS, -10000);
		lua_pushlightuserdata(LS, reinterpret_cast<void*>(NewUserdata));
		lua_rawget(LS, -2);

		lua_pushlightuserdata(LS, reinterpret_cast<void*>(NewUserdata));
		lua_pushnil(LS);
		lua_rawset(LS, -4);

		RBX::PushInstance(LS, (void*)OldUserdata);

		lua_pushlightuserdata(LS, reinterpret_cast<void*>(NewUserdata));
		lua_pushvalue(LS, -3);
		lua_rawset(LS, -5);

		return 1;
	}
	inline int compareinstances(lua_State* LS) {
		//("compareinstances");

		luaL_checktype(LS, 1, LUA_TUSERDATA);
		luaL_checktype(LS, 2, LUA_TUSERDATA);

		HelpFuncs::IsInstance(LS, 1);
		HelpFuncs::IsInstance(LS, 2);

		uintptr_t First = *reinterpret_cast<uintptr_t*>(lua_touserdata(LS, 1));
		if (!First)
			luaL_argerrorL(LS, 1, "Invalid instance");

		uintptr_t Second = *reinterpret_cast<uintptr_t*>(lua_touserdata(LS, 2));
		if (!Second)
			luaL_argerrorL(LS, 2, "Invalid instance");

		if (First == Second)
			lua_pushboolean(LS, true);
		else
			lua_pushboolean(LS, false);

		return 1;
	}
#define ArcticCapabilities (0x200000000000003FLL | 0xFFFFFFF00LL) | (1ull << 48ull)
	inline bool CheckProtoE(const Proto* _Proto, std::unordered_set<const Proto*>& ProtoList) {
		if (!_Proto || !_Proto->userdata || ProtoList.contains(_Proto)) {
			return false;
		}
		ProtoList.insert(_Proto);

		const auto* Capabilities = static_cast<const uint64_t*>(_Proto->userdata);
		if ((*Capabilities & ArcticCapabilities) == ArcticCapabilities) {
			return true;
		}

		if (_Proto->p && _Proto->sizep > 0) {
			for (int i = 0; i < _Proto->sizep; i++) {
				const auto Proto = _Proto->p[i];
				if (CheckProtoE(Proto, ProtoList)) {
					return true;
				}
			}
		}

		return false;
	}


	inline bool IsOurProto(const Proto* proto) {
		std::unordered_set<const Proto*> Protos;
		return CheckProtoE(proto, Protos);
	}
	inline int isexecutorclosure(lua_State* LS) {
		if (lua_type(LS, 1) != LUA_TFUNCTION) {
			lua_pushboolean(LS, false);
			return 1;
		}

		bool value = false;

		if (lua_isLfunction(LS, 1))
		{
			Closure* closure = (Closure*)lua_topointer(LS, 1);
			value = IsOurProto(closure->l.p);
		}
		else
		{
			Closure* closure = (Closure*)lua_topointer(LS, 1);
			value = Handler::ExecutorFunctions.contains(closure);
		}

		lua_pushboolean(LS, value);
		return 1;
	}



	inline int setfenv(lua_State* L) {
		luaL_checktype(L, 1, LUA_TFUNCTION);
		luaL_checktype(L, 2, LUA_TTABLE);
		lua_pushvalue(L, 1);
		lua_pushvalue(L, 2);
		lua_setfenv(L, -2);
		return 0;
	}

	inline int setthreadidentity(lua_State* L) {
		luaL_checktype(L, 1, LUA_TNUMBER);
		auto identity = lua_tointeger(L, 1);
		if (identity < 0) {
			luaL_error(L, "Invalid identity");
			return 0;
		}
		TaskScheduler::SetThreadCapabilities(L, identity, ~0ULL);

		return 0;
	}

	inline int getthreadidentity(lua_State* L) {
		auto extraSpace = (uintptr_t)(L->userdata);
		int res = *reinterpret_cast<int*>(extraSpace + 0x30);
		lua_pushinteger(L, res);
		return 1;
	}
	inline int setfps(lua_State* L) {
		luaL_checktype(L, 1, LUA_TNUMBER);
		auto fps = lua_tointeger(L, 1);
		if (fps < 0) {
			luaL_error(L, "Invalid FPS value");
			return 0;
		}
		TaskScheduler::SetFPS(fps);
		return 0;
	}
	inline int GetGenv(lua_State* L) {
		lua_pushvalue(L, LUA_ENVIRONINDEX);
		return 1;
	}
	inline int getsenv(lua_State* L) {

		luaL_checktype(L, 1, LUA_TUSERDATA);

		uintptr_t script = *(uintptr_t*)lua_touserdata(L, 1);

		if (!Utils::IsAddressValid(script) || !Utils::Utils::IsAddressValid(*(uintptr_t*)(script + Offsets::Properties::ClassDescriptor))) {
			lua_pushnil(L);
			return 1;
		}

		const char* className = *(const char**)(*(uintptr_t*)(script + Offsets::Properties::ClassDescriptor) + Offsets::Properties::ClassName);

		bool decrypt = true;
		std::string bytecode = "";

		if (strcmp(className, "LocalScript") != 0) {
			luaL_argerror(L, 1, "localscript");
		}

		const auto script_node = *reinterpret_cast<uintptr_t*>(script + Offsets::Thread::weak_thread_node);
		const auto node_weak_thread_ref = script_node ? *reinterpret_cast<uintptr_t*>(script_node + Offsets::Thread::weak_thread_ref) : NULL;
		const auto live_thread_ref = node_weak_thread_ref ? *reinterpret_cast<uintptr_t*>(node_weak_thread_ref + Offsets::Thread::weak_thread_ref_live) : NULL;
		const auto script_thread = live_thread_ref ? *reinterpret_cast<lua_State**>(live_thread_ref + Offsets::Thread::weak_thread_ref_live_thread) : NULL;

		if (!script_thread)
			luaL_error(L, "could not get script environment - localscript not running");

		lua_pushvalue(script_thread, LUA_GLOBALSINDEX);
		lua_xmove(script_thread, L, 1);

		return 1;
	}
	static bool IsMetamethod(const char* Metamethod)
	{
		if (std::string(Metamethod).empty())
			return false;

		const std::unordered_set<std::string> Allowed = {
			"__namecall",
			"__newindex",
			"__index"
		};
		return Allowed.find(Metamethod) != Allowed.end();
	};
	inline int hookmetamethod(lua_State* LS) {
		luaL_checkany(LS, 1);
		luaL_checkstring(LS, 2);
		luaL_checkany(LS, 3);

		if (!lua_getmetatable(LS, 1)) {
			lua_pushnil(LS);
			return 1;
		}

		int Table = lua_gettop(LS);
		const char* Method = lua_tostring(LS, 2);
		if (!IsMetamethod(Method))
			return 0;

		auto OldReadOnly = lua_getreadonly(LS, 1);

		lua_getfield(LS, Table, Method);
		lua_pushvalue(LS, -1);

		lua_setreadonly(LS, Table, false);

		lua_pushvalue(LS, 3);
		lua_setfield(LS, Table, Method);

		lua_setreadonly(LS, Table, OldReadOnly);

		lua_remove(LS, Table);

		return 1;
	};
	inline int newcclosure(lua_State* L) {
		luaL_checktype(L, 1, LUA_TFUNCTION);

		if (!lua_iscfunction(L, 1))
			return wrapclosure(L, 1);

		lua_pushvalue(L, 1);
		return 1;
	};
	inline int getgc(lua_State* L) {
		bool IncludeTables = lua_gettop(L) ? luaL_optboolean(L, 1, 0) : false;

		lua_newtable(L);

		struct CGarbageCollector
		{
			lua_State* L;
			int IncludeTables;
			int Count;
		} Gct{ L, IncludeTables, 0 };

		luaM_visitgco(L, &Gct, [](void* Context, lua_Page* Page, GCObject* Gco) {
			auto Gct = static_cast<CGarbageCollector*>(Context);

			if (!((Gco->gch.marked ^ WHITEBITS) & otherwhite(Gct->L->global)))
				return false;

			auto tt = Gco->gch.tt;
			if (tt == LUA_TFUNCTION || tt == LUA_TUSERDATA || (Gct->IncludeTables && tt == LUA_TTABLE))
			{
				Gct->L->top->value.gc = Gco;
				Gct->L->top->tt = Gco->gch.tt;
				Gct->L->top++;

				lua_rawseti(Gct->L, -2, ++Gct->Count);
			}
			return false;
			});

		return 1;
	}





}




namespace Http {
	static auto replace(std::string& str, const std::string& from, const std::string& to) -> bool
	{
		size_t start_pos = str.find(from);
		if (start_pos == std::string::npos)
			return false;
		str.replace(start_pos, from.length(), to);
		return true;
	}

	inline std::string replaceAll(std::string subject, const std::string& search, const std::string& replace)
	{
		size_t pos = 0;
		while ((pos = subject.find(search, pos)) != std::string::npos)
		{
			subject.replace(pos, search.length(), replace);
			pos += replace.length();
		}
		return subject;
	}
	inline int request(lua_State* L) {
		luaL_checktype(L, 1, LUA_TTABLE);

		// Fetch URL
		lua_getfield(L, 1, "Url");
		if (lua_type(L, -1) != LUA_TSTRING) {
			luaL_error(L, "Invalid or no 'Url' field specified in request table");
			return 0;
		}
		auto url = lua_tostring(L, -1);
		if (url == nullptr || strlen(url) == 0) {
			luaL_error(L, "'Url' field cannot be empty");
			return 0;
		}
		lua_pop(L, 1);

		// Fetch method (default to POST)
		lua_getfield(L, 1, "Method");
		auto method = std::string(luaL_optstring(L, -1, "POST"));
		lua_pop(L, 1);

		// Fetch body (if any)
		std::string body;
		lua_getfield(L, 1, "Body");
		if (lua_isstring(L, -1)) {
			body = luaL_checkstring(L, -1);
		}
		lua_pop(L, 1);

		// Fetch headers (if any)
		lua_getfield(L, 1, "Headers");
		bool hasHeaders = lua_istable(L, -1);
		lua_getglobal(L, "game");
		lua_getfield(L, -1, "JobId");
		std::string jobId = lua_tostring(L, -1);
		if (jobId.empty()) {
			luaL_error(L, "Invalid 'JobId' in game context");
			return 0;
		}
		lua_pop(L, 1);

		lua_getfield(L, -1, "GameId");
		std::string gameId = lua_tostring(L, -1);
		if (gameId.empty()) {
			luaL_error(L, "Invalid 'GameId' in game context");
			return 0;
		}
		lua_pop(L, 1);

		lua_getfield(L, -1, "PlaceId");
		std::string placeId = lua_tostring(L, -1);
		if (placeId.empty()) {
			luaL_error(L, "Invalid 'PlaceId' in game context");
			return 0;
		}
		lua_pop(L, 2);

		// Construct headers
		std::string headers = "Roblox-Session-Id: {\"GameId\":\"" + jobId + "\",\"PlaceId\":\"" + placeId + "\"}\r\n";
		headers += "Roblox-Game-Id: \"" + gameId + "\"\r\n";
		if (hasHeaders) {
			lua_pushnil(L);
			while (lua_next(L, -2)) {
				const char* headerKey = luaL_checkstring(L, -2);
				const char* headerValue = luaL_checkstring(L, -1);
				if (headerKey && headerValue) {
					headers += headerKey;
					headers += ": ";
					headers += headerValue;
					headers += "\r\n";
				}
				lua_pop(L, 1);
			}
		}
		lua_pop(L, 1);

		// Fetch cookies (if any)
		lua_getfield(L, 1, "Cookies");
		bool hasCookies = lua_istable(L, -1);
		std::string cookies;
		if (hasCookies) {
			lua_pushnil(L);
			while (lua_next(L, -2)) {
				const char* cookieName = luaL_checkstring(L, -2);
				const char* cookieValue = luaL_checkstring(L, -1);
				if (cookieName && cookieValue) {
					cookies += cookieName;
					cookies += "=";
					cookies += cookieValue;
					cookies += "; ";
				}
				lua_pop(L, 1);
			}
		}
		lua_pop(L, 1);

		headers += "User-Agent: CL_TEAM\r\n";

		// HWID check
		HW_PROFILE_INFO hwProfileInfo;
		if (!GetCurrentHwProfile(&hwProfileInfo)) {
			luaL_error(L, "Failed to retrieve hardware profile.");
			return 0;
		}

		std::string hwid = hwProfileInfo.szHwProfileGuid;
		if (hwid.empty()) {
			luaL_error(L, "Invalid HWID.");
			return 0;
		}

		replace(hwid, "}", "");
		replace(hwid, "{", "");
		headers += "Fingerprint: Cloudy-Fingerprint\r\n";
		if (!hwid.empty()) {
			headers += "Exploit-Guid: " + hwid + "\r\n";
			headers += "Cloudy-Fingerprint: " + hwid + "\r\n";
		}
		else {
			headers += "Exploit-Guid: Unknown\r\n";
		}

		// Open Internet session
		HINTERNET hSession = InternetOpen("CL_TEAM", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if (!hSession) {
			luaL_error(L, "Failed to open Internet session.");
			return 0;
		}

		HINTERNET hConnect = InternetOpenUrl(hSession, url, headers.c_str(), (DWORD)headers.length(), INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
		if (!hConnect) {
			InternetCloseHandle(hSession);
			luaL_error(L, "Failed to connect to URL.");
			return 0;
		}

		DWORD statusCode = 0;
		DWORD length = sizeof(DWORD);
		if (!HttpQueryInfo(hConnect, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &length, NULL)) {
			InternetCloseHandle(hConnect);
			InternetCloseHandle(hSession);
			luaL_error(L, "Failed to retrieve status code.");
			return 0;
		}

		// Prepare the response table
		lua_newtable(L);

		std::string responseText;
		char buffer[4096] = {};
		DWORD bytesRead;

		// Ensure that the reading from the connection is safe
		while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0) {
			if (bytesRead > 0) {
				responseText.append(buffer, bytesRead);
			}
			else {
				break;
			}
		}

		lua_pushlstring(L, responseText.data(), responseText.length());
		lua_setfield(L, -2, "Body");

		lua_pushinteger(L, statusCode);
		lua_setfield(L, -2, "StatusCode");

		lua_pushboolean(L, statusCode >= 200 && statusCode < 300);
		lua_setfield(L, -2, "Success");

		// Add headers to the response
		lua_newtable(L);
		if (hasHeaders) {
			lua_pushlstring(L, "Headers", 7);
			lua_newtable(L);
			lua_pushlstring(L, headers.c_str(), headers.length());
			lua_setfield(L, -2, "AllHeaders");
			lua_settable(L, -3);
		}
		lua_setfield(L, -2, "Headers");

		// Clean up
		InternetCloseHandle(hConnect);
		InternetCloseHandle(hSession);

		return 1;
	}
	inline std::string downloadUrl(lua_State* L, std::string URL)
	{
		HINTERNET interwebs = InternetOpen("Roblox/WinInet", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
		HINTERNET urlFile = nullptr;  // Declare only once
		std::string rtn;

		// Check Lua stack for game.JobId
		lua_getglobal(L, "game");
		lua_getfield(L, -1, "JobId");
		std::string jobId;
		if (lua_type(L, -1) == LUA_TSTRING) {
			jobId = lua_tostring(L, -1);
			lua_pop(L, 1);
		}
		else {
			lua_pop(L, 1);  // Pop invalid value if not a string
			return "Error: JobId is not a string!";
		}

		// Check Lua stack for game.GameId
		lua_getfield(L, -1, "GameId");
		std::string gameId;
		if (lua_type(L, -1) == LUA_TNUMBER) {
			gameId = std::to_string(lua_tonumber(L, -1));
			lua_pop(L, 1);
		}
		else {
			lua_pop(L, 1);  // Pop invalid value if not a string
			return "Error: GameId is not a number!";
		}

		// Check Lua stack for game.PlaceId
		lua_getfield(L, -1, "PlaceId");
		std::string placeId;
		if (lua_type(L, -1) == LUA_TNUMBER) {
			placeId = std::to_string(lua_tonumber(L, -1));
			lua_pop(L, 2);  // Pop both PlaceId and game
		}
		else {
			lua_pop(L, 2);  // Pop invalid value
			return "Error: PlaceId is not a number!";
		}

		const std::string headers = "Roblox-Session-Id: {\"GameId\":\"" + jobId + "\",\"PlaceId\":\"" + placeId + "\"}\r\nRoblox-Game-Id: \"" + gameId + "\"";

		if (interwebs)
		{
			urlFile = InternetOpenUrl(interwebs, URL.c_str(), headers.c_str(), static_cast<DWORD>(headers.length()), INTERNET_FLAG_RELOAD, 0);
			if (urlFile)
			{
				char buffer[2000]{};
				DWORD bytesRead = 0;
				do
				{
					if (!InternetReadFile(urlFile, buffer, sizeof(buffer), &bytesRead)) {
						return "Error: Failed to read from the URL!";
					}

					if (bytesRead > 0) {
						rtn.append(buffer, bytesRead);
					}

					memset(buffer, 0, sizeof(buffer));
				} while (bytesRead);

				InternetCloseHandle(urlFile);
			}
			else {
				return "Error: Failed to open URL!";
			}

			InternetCloseHandle(interwebs);
		}

		return replaceAll(rtn, "|n", "\r\n");
	}
	inline int httpget(lua_State* L) {
		luaL_checktype(L, 2, LUA_TSTRING);

		std::string url = lua_tostring(L, 2);
		std::string result = downloadUrl(L, url);

		lua_pushlstring(L, result.data(), result.size());

		return 1;
	}

}

using easywsclient::WebSocket;
namespace Websocket {
	static class exploit_websocket {
	public:
		lua_State* th = nullptr;
		bool connected = false;
		WebSocket::pointer webSocket = nullptr;
		std::thread pollThread;
		std::atomic<bool> running = false;

		int onMessageRef;
		int onCloseRef;
		int threadRef;

		inline void pollMessages() {
			while (running) {
				if (!webSocket || webSocket->getReadyState() != WebSocket::OPEN) {
					fireClose();
					break;
				}

				webSocket->poll(10); // Poll with a short timeout
				webSocket->dispatch([this](const std::string& message) {
					fireMessage(message);
					});

				std::this_thread::sleep_for(std::chrono::milliseconds(10));
			}
		}

		inline void fireMessage(const std::string& message) {
			if (!connected || !th) {
				return;
			}

			lua_getref(th, onMessageRef);
			lua_getfield(th, -1, "Fire");
			lua_getref(th, onMessageRef);
			lua_pushlstring(th, message.c_str(), message.size());

			if (lua_pcall(th, 2, 0, 0) != LUA_OK) {
				lua_settop(th, 0);
				return;
			}

			lua_settop(th, 0);
		}

		inline void fireClose() {
			if (!connected || !th) {
				return;
			}

			connected = false;
			running = false;

			lua_getref(th, onCloseRef);
			lua_getfield(th, -1, "Fire");
			lua_getref(th, onCloseRef);
			if (lua_pcall(th, 1, 0, 0) != LUA_OK) {
				luaL_error(th, lua_tostring(th, -1));
				return;
			}
			lua_settop(th, 0);

			// Unreference Lua functions
			lua_unref(th, onMessageRef);
			lua_unref(th, onCloseRef);
			lua_unref(th, threadRef);
		}

		inline int handleIndex(lua_State* ls) {
			if (!ls || !connected) return 0;

			luaL_checktype(ls, 1, LUA_TUSERDATA);
			std::string idx = luaL_checkstring(ls, 2);

			if (idx == "OnMessage") {
				lua_getref(ls, this->onMessageRef);
				lua_getfield(ls, -1, "Event");
				return 1;
			}
			else if (idx == "OnClose") {
				lua_getref(ls, this->onCloseRef);
				lua_getfield(ls, -1, "Event");
				return 1;
			}
			else if (idx == "Send") {
				lua_pushvalue(ls, -10003);
				lua_pushcclosure(ls,
					[](lua_State* L) -> int {
						if (!L) return 0;

						luaL_checktype(L, 1, LUA_TUSERDATA);
						std::string data = luaL_checkstring(L, 2);

						exploit_websocket* ws = reinterpret_cast<exploit_websocket*>(lua_touserdata(L, -10003));
						if (ws && ws->webSocket && ws->connected) {
							ws->webSocket->send(data);
						}
						return 0;
					}, "websocketinstance_send", 1);
				return 1;
			}
			else if (idx == "Close") {
				lua_pushvalue(ls, -10003);
				lua_pushcclosure(ls,
					[](lua_State* L) -> int {
						if (!L) return 0;

						exploit_websocket* ws = reinterpret_cast<exploit_websocket*>(lua_touserdata(L, -10003));
						if (ws && ws->webSocket) {
							ws->webSocket->close();
							ws->fireClose();
						}
						return 0;
					}, "websocketinstance_close", 1);
				return 1;
			}

			return 0;
		}

		inline bool reconnect(const std::string& url) {
			// Attempt reconnect logic, with retries and timeouts
			constexpr int maxRetries = 5;
			for (int i = 0; i < maxRetries; ++i) {
				webSocket = WebSocket::from_url(url);
				if (webSocket && webSocket->getReadyState() == WebSocket::OPEN) {
					return true;
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Delay before retry
			}
			return false;
		}
	};

	inline int connect(lua_State* ls) {
		luaL_checktype(ls, 1, LUA_TSTRING);
		std::string url = luaL_checkstring(ls, 1);

		exploit_websocket* ws = (exploit_websocket*)lua_newuserdata(ls, sizeof(exploit_websocket));
		new (ws) exploit_websocket{};

		ws->th = lua_newthread(ls);
		ws->threadRef = lua_ref(ls, -1);
		lua_pop(ls, 1);

		if (!ws->reconnect(url)) {
			luaL_error(ls, "Failed to connect");
			return 0;
		}

		lua_getglobal(ls, "Instance");
		lua_getfield(ls, -1, "new");
		lua_pushstring(ls, "BindableEvent");
		lua_pcall(ls, 1, 1, 0);
		ws->onMessageRef = lua_ref(ls, -1);
		lua_pop(ls, 2);

		// BindableEven
		lua_getglobal(ls, "Instance");
		lua_getfield(ls, -1, "new");
		lua_pushstring(ls, "BindableEvent");
		lua_pcall(ls, 1, 1, 0);
		ws->onCloseRef = lua_ref(ls, -1);
		lua_pop(ls, 2);

		ws->connected = true;
		ws->running = true;
		ws->pollThread = std::thread(&exploit_websocket::pollMessages, ws);

		lua_newtable(ls);
		lua_pushstring(ls, "WebSocket");
		lua_setfield(ls, -2, "__type");

		lua_pushvalue(ls, -2);
		lua_pushcclosure(ls,
			[](lua_State* L) -> int {
				exploit_websocket* ws = reinterpret_cast<exploit_websocket*>(lua_touserdata(L, lua_upvalueindex(1)));
				return ws->handleIndex(L);
			},
			"__index", 1);
		lua_setfield(ls, -2, "__index");
		lua_setmetatable(ls, -2);

		return 1;
	}
}
