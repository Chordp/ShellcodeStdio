#pragma once

#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include <iostream>
#include <fstream>
#include <string>
namespace ScStdio {
	VOID __stdcall MalCode(char* msg);
	BOOL WriteShellcodeToDisk();

	template<typename  ...Args>
	void Test(Args... args)
	{
		std::ifstream InFile("shellcode.bin", std::ios::in | std::ios::binary);
		auto pos = InFile.tellg();
		InFile.seekg(0, std::ios::end);
		size_t Length = InFile.tellg();
		InFile.seekg(pos);

		char* buffer = new char[Length];
		InFile.read(buffer, Length);
		DWORD dwProtext = 0;
		VirtualProtect(buffer, Length, PAGE_EXECUTE_READWRITE, &dwProtext);
		auto Entry = reinterpret_cast<void(_stdcall*)(Args...)>(buffer);
		Entry(args...);
	}
}