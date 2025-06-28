#pragma once
#include <Windows.h>

static class Utils {
private:
	
public:
	static bool IsAddressValid(uintptr_t addr);

	static bool InitializeClient();

	static void TpHandler();
	
	static bool isInjected;

	static void PatchDetection(void* targetFunction, size_t size);

};