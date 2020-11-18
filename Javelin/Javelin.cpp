// Javelin.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>
#include <filesystem>
#include <winternl.h>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>

#include "Libraries/termcolor/termcolor.hpp"

typedef NTSTATUS (NTAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
);

void* GetPebAddress(HANDLE ProcessHandle)
{
	const auto NtQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));
	PROCESS_BASIC_INFORMATION pbi;

	NtQueryInformationProcess(ProcessHandle, 0, &pbi, sizeof(pbi), nullptr);

	return pbi.PebBaseAddress;
}

int getmodules(DWORD processID)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
	                       PROCESS_VM_READ,
	                       FALSE, processID);
	if (nullptr == hProcess)
		return 1;

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
			                        sizeof(szModName) / sizeof(TCHAR)))
			{
				_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
			}
		}
	}

	// Release the handle to the process.

	CloseHandle(hProcess);

	return 0;
}

int main()
{
	std::cout << "[" << termcolor::green << "*" << termcolor::white << "] Loading cannons..." << std::endl;

	int detections = 0;
	bool syncheck = false;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	DWORD RPID = 0;

	auto* const snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (strcmp(entry.szExeFile, "RobloxPlayerBeta.exe") == 0)
			{
				RPID = entry.th32ProcessID;
			}
			if (strcmp(entry.szExeFile, "CefSharp.BrowserSubprocess.exe") == 0)
			{
				if (!syncheck)
				{
					DWORD value = MAX_PATH;
					char buffer[MAX_PATH];
					auto* h_process = OpenProcess(PROCESS_QUERY_INFORMATION, false, entry.th32ProcessID);
					QueryFullProcessImageName(h_process, 0, buffer, &value);
					CloseHandle(h_process);

					std::string libPath = buffer;
					if (!libPath.empty())
					{
						libPath.resize(libPath.size() - 30);
					}
					else
					{
						std::cout << "[" << termcolor::yellow << "*" << termcolor::white << "] A Synapse library was detected, but an error occurred when attempting to confirm the detection." << std::endl;
					}

					if (std::filesystem::exists(libPath + "SynapseInjector.dll"))
					{
						std::cout << "[" << termcolor::red << "*" << termcolor::white << "] Synapse has been detected to be running at " << libPath << std::endl;
					}
					else
					{
						std::cout << "[" << termcolor::red << "*" << termcolor::white << "] A Synapse library. However, Javelin could not confirm if it was Synapse. Look for more info at " << libPath << std::endl;
					}
					detections++;
					syncheck = true;
				}
			}
			else if (strcmp(entry.szExeFile, "rbxfpsunlocker.exe") == 0)
			{
				DWORD value = MAX_PATH;
				char buffer[MAX_PATH];
				auto* h_process = OpenProcess(PROCESS_QUERY_INFORMATION, false, entry.th32ProcessID);
				QueryFullProcessImageName(h_process, 0, buffer, &value);
				CloseHandle(h_process);
				std::cout << "[" << termcolor::yellow << "*" << termcolor::white << "] rbxfpsunlocker has been detected to be running at " << buffer << std::endl;
				detections++;
			}
			else if (strcmp(entry.szExeFile, "AutoHotkey.exe") == 0)
			{
				DWORD value = MAX_PATH;
				char buffer[MAX_PATH];
				auto* h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, entry.th32ProcessID);
				QueryFullProcessImageName(h_process, 0, buffer, &value);

				const auto peb = GetPebAddress(h_process);
				PVOID rtlUserProcParamsAddress;
				UNICODE_STRING cmdline;

				if (!ReadProcessMemory(h_process, &(static_cast<_PEB*>(peb)->ProcessParameters), &rtlUserProcParamsAddress, sizeof(PVOID), nullptr))
				{
					printf("Could not read the address of ProcessParameters!\n");
					return GetLastError();
				}

				if (!ReadProcessMemory(h_process, &(static_cast<_RTL_USER_PROCESS_PARAMETERS*>(rtlUserProcParamsAddress)->CommandLine),
					&cmdline, sizeof(cmdline), nullptr))
				{
					printf("Could not read CommandLine!\n");
					return GetLastError();
				}

				auto* const commandLineContents = static_cast<WCHAR*>(malloc(cmdline.Length));

				if (!ReadProcessMemory(h_process, cmdline.Buffer, commandLineContents, cmdline.Length, nullptr))
				{
					printf("Could not read the command line string!\n");
					return GetLastError();
				}
				CloseHandle(h_process);
				std::cout << "[" << termcolor::yellow << "*" << termcolor::white << "] AutoHotkey has been detected to be running at " << buffer << std::endl;
				std::cout << "[" << termcolor::yellow << "*" << termcolor::white << "] AutoHotkey Arguments: " << printf("%.*S", cmdline.Length / 2, commandLineContents) << std::endl;
				free(commandLineContents);
				detections++;
			}
		}
	}

	CloseHandle(snapshot);

	std::cout << std::endl;
	if (detections == 0)
	{
		std::cout << "[" << termcolor::green << "*" << termcolor::white << "] There were 0 total detections. Nice job, Javelin thinks you're legit!" << std::endl;
	}
	else
	{
		std::cout << "[" << termcolor::red << "*" << termcolor::white << "] There were " << detections << " total detections." << std::endl;
	}

	std::cout << std::endl;

	if (RPID) {
		std::cout << "[" << termcolor::green << "*" << termcolor::white << "] Here are all the modules currently hooked to RobloxPlayerBeta.exe" << std::endl;
		getmodules(RPID);
	}
	
	std::cout << "AZURILEX ON UR BITCH" << std::endl;

	system("PAUSE");

	return 0;
}
