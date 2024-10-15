#pragma once
#include "includes.h"

struct Globals
{
	static Globals* Get()
	{
		static auto* instance = new Globals();
		return instance;
	}

	int MenuTab = 0;

	std::vector<std::string> Games = { "Cleaner","Spoofer","Mac Changer" };
	int Game = 0;

	bool AutoInject = false;
	bool Blockreports = false;
	bool SafeInjection = true;
};