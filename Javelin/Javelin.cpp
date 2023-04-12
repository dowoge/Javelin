// Javelin.cpp : This file contains the 'main' function. Program execution begins and ends there.
// Code edited slightly

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

using namespace std;

//type for the return of queryinformation
typedef NTSTATUS (NTAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
);
//helper function that returns the PEB address for a specific process (PEB addresses are like OS architecture, x64, x86, etc...)
void* GetPebAddress(HANDLE ProcessHandle)
{
	const auto NtQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));
	PROCESS_BASIC_INFORMATION pbi;

	NtQueryInformationProcess(ProcessHandle, 0, &pbi, sizeof(pbi), nullptr);

	return pbi.PebBaseAddress;
}
//get all the modules loaded by a certain process and dump them to the output
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
	cout << termcolor::underline << "Javelin (by Azurilex aka rate) edited by tommy" << endl;
	
	// process detection

	cout << "[" << termcolor::green << "*" << termcolor::white << "] Loading cannons..." << endl;

	int detections = 0;

	bool syncheck = false;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	DWORD RPID = 0;

	auto* const snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL); // capture all curently loaded processes (like the name implies, its a snapshot)
	//begin going through the processes
	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (strcmp(entry.szExeFile, "RobloxPlayerBeta.exe") == 0) //if the process is from the RobloxPlayerBeta.exe file
			{
				RPID = entry.th32ProcessID; //save the process id for future reference (since this is the process we want to examine)
			}
			if (strcmp(entry.szExeFile, "CefSharp.BrowserSubprocess.exe") == 0) // if a process is from the CefSharp.BrowserSubprocess.exe file
			{
				if (!syncheck) //if we havent already checked for synapse injection
				{
					DWORD value = MAX_PATH;
					char buffer[MAX_PATH];
					auto* h_process = OpenProcess(PROCESS_QUERY_INFORMATION, false, entry.th32ProcessID);
					QueryFullProcessImageName(h_process, 0, buffer, &value);
					CloseHandle(h_process);

					string libPath = buffer;

					if (!libPath.empty()) //if the file actually leads to somewhere
					{
						libPath.resize(libPath.size() - 30); //reduce path length by 30 to find the presumed root folder of synapse i.e.: "synapse v2\bin\CefSharp.BrowserSubprocess.exe" "synapse v2\bin\"
					}
					else
					{
						cout << "[" << termcolor::yellow << "*" << termcolor::white << "] A Synapse library was detected, but an error occurred when attempting to confirm the detection." << endl; //if the path doesnt to the .exe doesnt exist
					}
					if (filesystem::exists(libPath + "SynapseInjector.dll")) // if we find a file called "SynapseInjector.dll" under the now length-reduced libPath string then
					{
						cout << "[" << termcolor::red << "*" << termcolor::white << "] Synapse has been detected to be running at " << libPath << endl; //hooray, detected
					}
					else
					{
						cout << "[" << termcolor::red << "*" << termcolor::white << "] A Synapse library. However, Javelin could not confirm if it was Synapse. Look for more info at " << libPath << endl; //if we cant point to a synapse file we display the directory where the process originates from
					}
					// add to detections and note that the synapse check was ran
					detections++;
					syncheck = true;
				}
			}
			else if (strcmp(entry.szExeFile, "rbxfpsunlocker.exe") == 0) //if the process is from the rbxfpsunlocker.exe file
			{
				DWORD value = MAX_PATH;
				char buffer[MAX_PATH];
				auto* h_process = OpenProcess(PROCESS_QUERY_INFORMATION, false, entry.th32ProcessID);
				QueryFullProcessImageName(h_process, 0, buffer, &value); //get the process' origin directory
				CloseHandle(h_process);
				cout << "[" << termcolor::yellow << "*" << termcolor::white << "] rbxfpsunlocker has been detected to be running at " << buffer << endl; //self explanatory
				detections++;
			}
			else if (strcmp(entry.szExeFile, "AutoHotkey.exe") == 0 || strcmp(entry.szExeFile, "AutoHotkeyUX.exe") == 0) // if the process is from AutoHotkey.exe (AHK v1) or AutoHotkeyUX.exe (AHK v2)
			{
				DWORD value = MAX_PATH;
				char buffer[MAX_PATH];
				auto* h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, entry.th32ProcessID);
				QueryFullProcessImageName(h_process, 0, buffer, &value); //also get the process' origin directory

				const auto peb = GetPebAddress(h_process); //get the PEB address for the AHK process (refer to the comment above the GetPebAddress function to know what a PEB address is, line 27)
				PVOID rtlUserProcParamsAddress;
				UNICODE_STRING cmdline;

				if (!ReadProcessMemory(h_process, &(static_cast<_PEB*>(peb)->ProcessParameters), &rtlUserProcParamsAddress, sizeof(PVOID), nullptr)) //attempt to get the arguments of which ahk was ran with
				{
					printf("Could not read the address of ProcessParameters!\n");
					return GetLastError();
				}

				if (!ReadProcessMemory(h_process, &(static_cast<_RTL_USER_PROCESS_PARAMETERS*>(rtlUserProcParamsAddress)->CommandLine), //basically the same as above just in a slightly different place
					&cmdline, sizeof(cmdline), nullptr))
				{
					printf("Could not read CommandLine!\n");
					return GetLastError();
				}

				auto* const commandLineContents = static_cast<WCHAR*>(malloc(cmdline.Length));

				if (!ReadProcessMemory(h_process, cmdline.Buffer, commandLineContents, cmdline.Length, nullptr)) //if ahk was started through cmd this should get the arguments it was started with
				{
					printf("Could not read the command line string!\n");
					return GetLastError();
				}
				CloseHandle(h_process);
				cout << "[" << termcolor::yellow << "*" << termcolor::white << "] AutoHotkey has been detected to be running at " << buffer << endl;
				cout << "[" << termcolor::yellow << "*" << termcolor::white << "] AutoHotkey Arguments: " << printf("%.*S", cmdline.Length / 2, commandLineContents) << endl;
				free(commandLineContents);
				detections++;
			}
		}
	}
	//we can stop holding onto the snapshot since we ran our tests
	CloseHandle(snapshot);

	// driver detection?

	LPVOID drivers[1024];
	DWORD cbn;
	int cDrivers, i;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbn) && cbn < sizeof(drivers)) { //check if we can enumerate all drivers and get them
		TCHAR szDriver[1024];
		cDrivers = cbn / sizeof(drivers[0]);

		cout << "\nFound " << termcolor::yellow << cDrivers << termcolor::white << " drivers loaded" << endl;

		for (i = 0; i < cDrivers; i++) { //go through all the drivers
			if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))) { //get the driver's name
				if (strcmp(szDriver, "rawaccel.sys") == 0) { //check if the driver's name is "rawaccel.sys"
					cout << "[" << termcolor::red << "*" << termcolor::white << "] RawAccel driver found to be loaded on system" << endl;
					detections++;
				}
			}
		}
	} else {
		_tprintf(TEXT("Could not EnumDeviceDrivers; array size needed is %zd\n"), cbn / sizeof(LPVOID));
		return GetLastError();
	}
	
	cout << endl;
	if (detections == 0) //no detections
	{
		cout << "[" << termcolor::green << "*" << termcolor::white << "] There were 0 total detections. Nice job, Javelin thinks you're legit!" << endl;
	}
	else //more than 1 detection
	{
		cout << "[" << termcolor::red << "*" << termcolor::white << "] There were " << detections << " total detections." << endl;
	}

	cout << endl;

	if (RPID) { //if we ended up finding the roblox process, we dump all the modules attached to it
		cout << "[" << termcolor::green << "*" << termcolor::white << "] Here are all the modules currently hooked to RobloxPlayerBeta.exe" << endl;
		getmodules(RPID);
	}

	system("PAUSE");

	return 0;
}
