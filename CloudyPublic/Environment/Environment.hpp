#pragma once
//#include <Luau/Compiler.h>
//#include <Luau/BytecodeBuilder.h>
//#include <Luau/BytecodeUtils.h>
//#include <Luau/Bytecode.h>
//
//#include <lapi.h>
//#include <lstate.h>
//#include <lualib.h>

#include "Functions.hpp"

namespace GameHooks {
    inline lua_CFunction OriginalNamecall;
    inline lua_CFunction OriginalIndex;
    static std::vector<const char*> dangerousFunctions =
    {
        "OpenVideosFolder", "OpenScreenshotsFolder",
        "GetRobuxBalance", "PerformPurchase", "PromptBundlePurchase", "PromptNativePurchase",
        "PromptProductPurchase", "PromptPurchase", "PromptThirdPartyPurchase", "Publish",
        "GetMessageId", "OpenBrowserWindow", "RequestInternal", "ExecuteJavaScript",
        "openvideosfolder", "openscreenshotsfolder", "getrobuxbalance", "performpurchase",
        "promptbundlepurchase", "promptnativepurchase", "promptproductpurchase",
        "promptpurchase", "promptthirdpartypurchase", "publish", "getmessageid",
        "openbrowserwindow", "requestinternal", "executejavascript", "openVideosFolder",
        "openScreenshotsFolder", "getRobuxBalance", "performPurchase", "promptBundlePurchase",
        "promptNativePurchase", "promptProductPurchase", "promptPurchase",
        "promptThirdPartyPurchase", "publish", "getMessageId", "openBrowserWindow",
        "requestInternal", "executeJavaScript",
        "ToggleRecording", "TakeScreenshot", "HttpRequestAsync", "GetLast",
        "SendCommand", "GetAsync", "GetAsyncFullUrl", "RequestAsync", "MakeRequest",
        "togglerecording", "takescreenshot", "httprequestasync", "getlast",
        "sendcommand", "getasync", "getasyncfullurl", "requestasync", "makerequest",
        "toggleRecording", "takeScreenshot", "httpRequestAsync", "getLast",
        "sendCommand", "getAsync", "getAsyncFullUrl", "requestAsync", "makeRequest", "AddCoreScriptLocal",
        "SaveScriptProfilingData", "GetUserSubscriptionDetailsInternalAsync",
        "GetUserSubscriptionStatusAsync", "PerformBulkPurchase", "PerformCancelSubscription",
        "PerformPurchaseV2", "PerformSubscriptionPurchase", "PerformSubscriptionPurchaseV2",
        "PrepareCollectiblesPurchase", "PromptBulkPurchase", "PromptCancelSubscription",
        "PromptCollectiblesPurchase", "PromptGamePassPurchase", "PromptNativePurchaseWithLocalPlayer",
        "PromptPremiumPurchase", "PromptRobloxPurchase", "PromptSubscriptionPurchase",
        "ReportAbuse", "ReportAbuseV3", "ReturnToJavaScript", "OpenNativeOverlay",
        "OpenWeChatAuthWindow", "EmitHybridEvent", "OpenUrl", "PostAsync", "PostAsyncFullUrl",
        "RequestLimitedAsync", "Run", "CaptureScreenshot", "CreatePostAsync",
        "DeleteCapture", "DeleteCapturesAsync", "GetCaptureFilePathAsync", "SaveCaptureToExternalStorage",
        "SaveCapturesToExternalStorageAsync", "GetCaptureUploadDataAsync", "RetrieveCaptures",
        "SaveScreenshotCapture", "Call", "GetProtocolMethodRequestMessageId",
        "GetProtocolMethodResponseMessageId", "PublishProtocolMethodRequest",
        "PublishProtocolMethodResponse", "Subscribe", "SubscribeToProtocolMethodRequest",
        "SubscribeToProtocolMethodResponse", "GetDeviceIntegrityToken", "GetDeviceIntegrityTokenYield",
        "NoPromptCreateOutfit", "NoPromptDeleteOutfit", "NoPromptRenameOutfit", "NoPromptSaveAvatar",
        "NoPromptSaveAvatarThumbnailCustomization", "NoPromptSetFavorite", "NoPromptUpdateOutfit",
        "PerformCreateOutfitWithDescription", "PerformRenameOutfit", "PerformSaveAvatarWithDescription",
        "PerformSetFavorite", "PerformUpdateOutfit", "PromptCreateOutfit", "PromptDeleteOutfit",
        "PromptRenameOutfit", "PromptSaveAvatar", "PromptSetFavorite", "PromptUpdateOutfit"
    };
    inline int NewNamecall(lua_State* L) {
        if (!L)
            return 0;

        if (L->userdata->Identity >= 8 && L->userdata->Script.expired()) {
            const char* data = L->namecall->data;

            if (strcmp(data, "HttpGet") == 0 || strcmp(data, "HttpGetAsync") == 0) {
                return Http::httpget(L);
            }

            for (const std::string& func : dangerousFunctions) {
                if (std::string(data) == func) {
                    luaL_error(L, "Function has been disabled for security reasons.");
                    return 0;
                }
            }
        }

        if (!OriginalNamecall)
            return 0;

        return OriginalNamecall(L);
    }
    inline int NewIndex(lua_State* L) {
        if (!L)
            return 0;

        if (L->userdata->Identity >= 8 && L->userdata->Script.expired()) {
            const char* data = lua_tostring(L, 2);

            if (strcmp(data, "HttpGet") == 0 || strcmp(data, "HttpGetAsync") == 0) {
                lua_getglobal(L, "HttpGet");
                return 1;
            }

            for (const std::string& func : dangerousFunctions) {
                if (std::string(data) == func) {
                    luaL_error(L, "Blacklisted function called.");
                    return 0;
                }
            }
        }

        if (!OriginalIndex)
            return 0;

        return OriginalIndex(L);
    }
    inline void InitializeHooks(lua_State* L) {
        int originalCount = lua_gettop(L);

        lua_getglobal(L, "game");
        luaL_getmetafield(L, -1, "__index");

        Closure* Index = clvalue(luaA_toobject(L, -1));
        OriginalIndex = Index->c.f;
        Index->c.f = NewIndex;

        lua_pop(L, 1);

        luaL_getmetafield(L, -1, "__namecall");

        Closure* Namecall = clvalue(luaA_toobject(L, -1));
        OriginalNamecall = Namecall->c.f;
        Namecall->c.f = NewNamecall;

        lua_settop(L, originalCount);
    }
}
namespace Environment {
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
        ExecutorFunctions.insert(closure);
        lua_ref(L, -1);
    }
    static void NewFunction(lua_State* L, const char* globalname, lua_CFunction function)
    {
        PushClosure(L, function, nullptr, 0);
        ExecutorFunctions.insert(*reinterpret_cast<Closure**>(index2addr(L, -1)));
        lua_setfield(L, LUA_GLOBALSINDEX, globalname);
    }

    static void NewTableFunction(lua_State* L, const char* globalname, lua_CFunction function)
    {
        PushClosure(L, function, nullptr, 0);
        ExecutorFunctions.insert(*reinterpret_cast<Closure**>(index2addr(L, -1)));
        lua_setfield(L, -2, globalname);
    }

    inline void Init(lua_State* LS) {
        //NewFunction(LS, "gettenv", Base::gettenv);
        NewFunction(LS, "getrenv", Misc::getrenv);
        NewFunction(LS, "getgc", Misc::getgc);
        NewFunction(LS, "loadstring", Misc::loadstring);
        NewFunction(LS, "newcclosure", Misc::newcclosure);

        NewFunction(LS, "getexecutorname", Misc::getexecutorname);
        NewFunction(LS, "lz4compress", Misc::lz4compress);
        NewFunction(LS, "lz4decompress", Misc::lz4decompress);
        NewFunction(LS, "messagebox", Misc::messagebox);
        NewFunction(LS, "setclipboard", Misc::setclipboard);
        NewFunction(LS, "toclipboard", Misc::setclipboard);
        NewFunction(LS, "queue_on_teleport", Misc::queue_on_teleport);
        NewFunction(LS, "queueonteleport", Misc::queue_on_teleport);
        NewFunction(LS, "getinstances", Misc::getinstances);
        NewFunction(LS, "getnilinstances", Misc::getnilinstances);
        NewFunction(LS, "getscripts", Misc::getscripts);
        NewFunction(LS, "getrunningscripts", Misc::getrunningscripts);
        NewFunction(LS, "getloadedmodules", Misc::getloadedmodules);
        NewFunction(LS, "fireclickdetector", Misc::fireclickdetector);
        NewFunction(LS, "firetouchinterest", Misc::firetouchinterest);
        NewFunction(LS, "fireproximityprompt", Misc::fireproximityprompt);
        NewFunction(LS, "gethui", Misc::gethui);
        NewFunction(LS, "getcallbackvalue", Misc::getcallbackvalue);
        NewFunction(LS, "isscriptable", Misc::isscriptable);
        NewFunction(LS, "setscriptable", Misc::setscriptable);
        NewFunction(LS, "getscriptclosure", Misc::getscriptclosure);
        NewFunction(LS, "getscriptfunction", Misc::getscriptclosure);
        //NewFunction(LS, "getscriptbytecode", Misc::getscriptbytecode);
        //NewFunction(LS, "dumpstring", Misc::getscriptbytecode);
        NewFunction(LS, "getcallingscript", Misc::getcallingscript);
        NewFunction(LS, "getscripthash", Misc::getscripthash);

        //NewFunction(LS, "keypress", Base::Input::keypress);
        //NewFunction(LS, "keytap", Base::Input::keytap);
        //NewFunction(LS, "keyrelease", Base::Input::keyrelease);
        //NewFunction(LS, "mouse1click", Base::Input::mouse1click);
        //NewFunction(LS, "mouse1press", Base::Input::mouse1press);
        //NewFunction(LS, "mouse1release", Base::Input::mouse1release);
        //NewFunction(LS, "mouse2click", Base::Input::mouse2click);
        //NewFunction(LS, "mouse2press", Base::Input::mouse2press);
        //NewFunction(LS, "mouse2release", Base::Input::mouse2release);
        //NewFunction(LS, "mousemoveabs", Base::Input::mousemoveabs);
        //NewFunction(LS, "mousemoverel", Base::Input::mousemoverel);
        //NewFunction(LS, "mousescroll", Base::Input::mousescroll);

        lua_newtable(LS);
        NewTableFunction(LS, "invalidate", Misc::invalidate);
        NewTableFunction(LS, "iscached", Misc::iscached);
        NewTableFunction(LS, "replace", Misc::replace);
        lua_setfield(LS, LUA_GLOBALSINDEX, ("cache"));

        NewFunction(LS, "cloneref", Misc::cloneref);
        NewFunction(LS, "compareinstances", Misc::compareinstances);

        NewFunction(LS, "getrawmetatable", Misc::getrawmetatable);
        NewFunction(LS, "setrawmetatable", Misc::setrawmetatable);
        NewFunction(LS, "isreadonly", Misc::isreadonly);
        NewFunction(LS, "setreadonly", Misc::setreadonly);
        NewFunction(LS, "getnamecallmethod", Misc::getnamecallmethod);
        NewFunction(LS, "hookfunction", Misc::hookfunction);
        NewFunction(LS, "replacefunction", Misc::hookfunction);
        NewFunction(LS, "replaceclosure", Misc::hookfunction);
        NewFunction(LS, "hookmetamethod", Misc::hookmetamethod);
        NewFunction(LS, "getreg", Misc::getreg);
        NewFunction(LS, "getregistry", Misc::getreg);
        NewFunction(LS, "getstack", Misc::getstack);
        NewFunction(LS, "getsenv", Misc::getsenv);

        lua_getglobal(LS, "debug");
        lua_getglobal(LS, "setreadonly");
        lua_pushvalue(LS, -2);
        lua_pushboolean(LS, false);
        lua_pcall(LS, 2, 0, 0);

        NewTableFunction(LS, "getreg", Misc::getreg);
        NewTableFunction(LS, "getregistry", Misc::getreg);
        NewTableFunction(LS, "getstack", Misc::getstack);
        NewTableFunction(LS, "getinfo", Misc::getinfo);//
        NewTableFunction(LS, "getupvalue", Misc::getupvalue);
        NewTableFunction(LS, "getupvalues", Misc::getupvalues);
        NewTableFunction(LS, "getconstants", Misc::getconstants);
        NewTableFunction(LS, "setconstant", Misc::setconstant);
        NewTableFunction(LS, "setstack", Misc::setstack);
        NewTableFunction(LS, "setupvalue", Misc::debug_setupvalue);
        NewTableFunction(LS, "getproto", Misc::getproto);
        NewTableFunction(LS, "getprotos", Misc::getprotos);
        lua_pop(LS, 1);

        NewFunction(LS, "getcustomasset", Filesystem::getcustomasset);
        NewFunction(LS, "writefile", Filesystem::writefile);
        NewFunction(LS, "readfile", Filesystem::readfile);
        NewFunction(LS, "makefolder", Filesystem::makefolder);
        NewFunction(LS, "isfolder", Filesystem::isfolder);
        NewFunction(LS, "delfile", Filesystem::delfile);
        NewFunction(LS, "appendfile", Filesystem::appendfile);
        NewFunction(LS, "delfolder", Filesystem::delfolder);
        NewFunction(LS, "isfile", Filesystem::isfile);
        NewFunction(LS, "listfiles", Filesystem::listfiles);
        NewFunction(LS, "loadfile", Filesystem::loadfile);

        NewFunction(LS, "iscclosure", Misc::iscclosure);
        NewFunction(LS, "is_c_closure", Misc::iscclosure);
        NewFunction(LS, "islclosure", Misc::islclosure);
        NewFunction(LS, "is_l_closure", Misc::islclosure);
        NewFunction(LS, "clonefunction", Misc::clonefunction);
        NewFunction(LS, "checkcaller", Misc::checkcaller);
        NewFunction(LS, "isexecutorclosure", Misc::isexecutorclosure);
        NewFunction(LS, "isourclosure", Misc::isexecutorclosure);
        NewFunction(LS, "checkclosure", Misc::isexecutorclosure);
        NewFunction(LS, "getfunctionhash", Misc::getfunctionhash);

        NewFunction(LS, "base64_encode", Crypt::base64encode);
        NewFunction(LS, "base64_decode", Crypt::base64decode);

        lua_newtable(LS);
        NewTableFunction(LS, "encode", Crypt::base64encode);
        NewTableFunction(LS, "decode", Crypt::base64decode);
        lua_setfield(LS, LUA_GLOBALSINDEX, ("base64"));

        lua_newtable(LS);
        NewTableFunction(LS, "base64encode", Crypt::base64encode);
        NewTableFunction(LS, "base64decode", Crypt::base64decode);
        NewTableFunction(LS, "base64_encode", Crypt::base64encode);
        NewTableFunction(LS, "base64_decode", Crypt::base64decode);

        lua_newtable(LS);
        NewTableFunction(LS, "encode", Crypt::base64encode);
        NewTableFunction(LS, "decode", Crypt::base64decode);
        lua_setfield(LS, -2, ("base64"));

        NewTableFunction(LS, "encrypt", Crypt::encrypt);
        NewTableFunction(LS, "decrypt", Crypt::decrypt);
        NewTableFunction(LS, "generatebytes", Crypt::generatebytes);
        NewTableFunction(LS, "generatekey", Crypt::generatekey);
        NewTableFunction(LS, "hash", Crypt::hash);
        lua_setfield(LS, LUA_GLOBALSINDEX, ("crypt"));


        lua_newtable(LS);
        NewTableFunction(LS, "request", Http::request);
        lua_setfield(LS, LUA_GLOBALSINDEX, ("http"));
        ////NewFunction(LS, "firesignal", Base::Signals::firesignal);

        NewFunction(LS, "HttpGet", Http::httpget);
        NewFunction(LS, "request", Http::request);
        NewFunction(LS, "http_request", Http::request);
        NewFunction(LS, "setthreadidentity", Misc::setthreadidentity);
        NewFunction(LS, "getthreadidentity", Misc::getthreadidentity);
        NewFunction(LS, "setidentity", Misc::setthreadidentity);
        NewFunction(LS, "getidentity", Misc::getthreadidentity);
        NewFunction(LS, "setthreadcontext", Misc::setthreadidentity);
        NewFunction(LS, "getthreadcontext", Misc::getthreadidentity);
        NewFunction(LS, "setfpscap", Misc::getthreadidentity);
        NewFunction(LS, "setfps", Misc::getthreadidentity);
        NewFunction(LS, "getgenv", Misc::GetGenv);
        NewFunction(LS, "gettenv", Misc::gettenv);
        NewFunction(LS, "identifyexecutor", Misc::identifyexecutor);
        NewFunction(LS, "getexecutorname", Misc::identifyexecutor);
        NewFunction(LS, "isrbxactive", Misc::isrbxactive);
        NewFunction(LS, "isgameactive", Misc::isrbxactive);


        // CUSTOM CLOUDY LIBRARY
        lua_newtable(LS);
        NewTableFunction(LS, "detections", Misc::detections);
        lua_setfield(LS, LUA_GLOBALSINDEX, ("cloudy"));

        lua_newtable(LS);
        NewTableFunction(LS, "connect", Websocket::connect);
        lua_setfield(LS, LUA_GLOBALSINDEX, ("WebSocket"));


        GameHooks::InitializeHooks(LS);


        lua_newtable(LS);
        lua_setglobal(LS, "_G");

        lua_newtable(LS);
        lua_setglobal(LS, "shared");

        lua_getglobal(LS, "game");
        lua_getfield(LS, -1, "GetService");
        lua_pushvalue(LS, -2);
        lua_pushstring(LS, "CoreGui");
        lua_call(LS, 2, 1);

        lua_getglobal(LS, "cloneref");
        lua_insert(LS, -2);
        lua_call(LS, 1, 1);

        lua_newtable(LS);
        lua_setglobal(LS, "cleardrawcache");

        lua_newtable(LS);
        lua_setglobal(LS, "setrenderproperty");

        lua_newtable(LS);
        lua_setglobal(LS, "getrenderproperty");

        lua_setglobal(LS, "__hiddeninterface");

        lua_newtable(LS);
        lua_setglobal(LS, "isrenderobj");

        Execution->Execute(Globals::ExploitThread, R"(
            loadstring(game:HttpGet("https://getcloudy.xyz/v1/draw.lua"))()

            warn("Drawing Registered!")
)", LUAU_LOAD);
    };

}