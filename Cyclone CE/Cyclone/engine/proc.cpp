#include "engine.h"
using namespace engine;

LPVOID mem::allocHeap(SIZE_T memSize) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, memSize);
}

bool mem::freeHeap(LPVOID mem) {
	return HeapFree(GetProcessHeap(), 0, mem) == 1 ? true : false;
}

HANDLE proc::openProcess(DWORD processId) {
	HANDLE hProc;

	OBJECT_ATTRIBUTES objAtt = { 0 };
	CLIENT_ID cid = { 0 };

	cid.UniqueProcess = (HANDLE)processId;
	cid.UniqueThread = 0;

	Sw3NtOpenProcess(
		&hProc,
		PROCESS_DUP_HANDLE | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
		&objAtt,
		&cid
	);

	return hProc;
}

HANDLE proc::openThread(DWORD threadId) {
	HANDLE hThr;

	OBJECT_ATTRIBUTES objAtt = { 0 };
	CLIENT_ID cid = { 0 };

	cid.UniqueThread = (HANDLE)threadId;
	cid.UniqueProcess = 0;

	Sw3NtOpenThread(
		&hThr,
		THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
		&objAtt,
		&cid
	);
}

DWORD proc::getProcId(const wchar_t* targetProcessName) {
	ULONG infoSize = 0;
	Sw3NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &infoSize);
	LPVOID pProcessInfo = mem::allocHeap(infoSize);

	Sw3NtQuerySystemInformation(SystemProcessInformation, pProcessInfo, infoSize, &infoSize);
	auto processInfo = (PSYSTEM_PROCESS_INFORMATION)pProcessInfo;

	while (processInfo->NextEntryOffset != NULL) {

		processInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)processInfo + processInfo->NextEntryOffset);
		PWSTR processName = processInfo->ImageName.Buffer;

		if (wcscmp(processName, targetProcessName) == 0) {
			mem::freeHeap(pProcessInfo);
			return (DWORD)processInfo->UniqueProcessId;
		}
	}

	mem::freeHeap(pProcessInfo);
}

vector<SYSTEM_THREAD_INFORMATION> proc::getProcThreadsInfo(DWORD processId) {
	vector<SYSTEM_THREAD_INFORMATION> procThreads;
	ULONG infoSize = 0;
	Sw3NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &infoSize);
	LPVOID pProcessInfo = mem::allocHeap(infoSize);

	Sw3NtQuerySystemInformation(SystemProcessInformation, pProcessInfo, infoSize, &infoSize);
	auto processInfo = (PSYSTEM_PROCESS_INFORMATION)pProcessInfo;

	while (processInfo->NextEntryOffset != NULL) {

		processInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)processInfo + processInfo->NextEntryOffset);
		DWORD targetProcessId = (DWORD)processInfo->UniqueProcessId;

		if (processId == targetProcessId) {

			for (size_t i = 0; i < processInfo->NumberOfThreads; i++)
			{
				SYSTEM_THREAD_INFORMATION threadInfo = processInfo->Threads[i];

				procThreads.push_back(threadInfo);
			}
		}
	}

	mem::freeHeap(pProcessInfo);

	return procThreads;
}
vector<HANDLE> proc::getProcThreads(DWORD processId) {
	vector<HANDLE> threads;
	auto threadsInfo = getProcThreadsInfo(processId);
	for (auto& tInfo : threadsInfo) {
		threads.push_back(
			openThread(
				(DWORD)tInfo.ClientId.UniqueThread
			)
		);
	}
	return threads;
}

bool proc::suspendThread(HANDLE thread) {
	NTSTATUS okSuspend = Sw3NtSuspendThread(
		thread,
		NULL
	);

	return NT_SUCCESS(okSuspend);
}
bool proc::resumeThread(HANDLE thread) {
	NTSTATUS okResume = Sw3NtResumeThread(
		thread,
		NULL
	);

	return NT_SUCCESS(okResume);
}
vector<RTL_PROCESS_MODULE_INFORMATION> proc::getKernelModulesInfo() {
	vector<RTL_PROCESS_MODULE_INFORMATION> kernelModules;
	ULONG infoSize = 0;
	Sw3NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &infoSize);
	LPVOID pProcessInfo = mem::allocHeap(infoSize);

	Sw3NtQuerySystemInformation(SystemModuleInformation, pProcessInfo, infoSize, &infoSize);
	auto modulesInfo = (PRTL_PROCESS_MODULES)pProcessInfo;

	for (size_t i = 0; i < modulesInfo->NumberOfModules; i++)
	{
		RTL_PROCESS_MODULE_INFORMATION moduleInfo = modulesInfo->Modules[i];
		kernelModules.push_back(moduleInfo);
	}

	return kernelModules;
}

vector<MODULEENTRY32W> proc::getProcModulesInfo(DWORD processId) {
	vector<MODULEENTRY32W> procModules;

	MODULEENTRY32W mod32 = { 0 };
	mod32.dwSize = sizeof(MODULEENTRY32W);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);

	Module32FirstW(snapshot, &mod32);

	while (Module32NextW(snapshot, &mod32)) {
		procModules.push_back(mod32);
		
	}

	return procModules;
}

std::optional<MODULEENTRY32W> proc::getModule(DWORD processId, const wchar_t* moduleName) {
	auto modules = getProcModulesInfo(processId);
	for (auto& procModule : modules) {
		auto name = procModule.szModule;
		if (wcscmp(name, moduleName) == 0) {
			return std::make_optional<MODULEENTRY32W>(procModule);
		}
	}
	return std::nullopt;
}
PVOID proc::getModuleBase(DWORD processId, const wchar_t* moduleName) {
	auto modules = getProcModulesInfo(processId);
	for (auto& procModule : modules) {
		auto name = procModule.szModule;
		if (wcscmp(name, moduleName) == 0) {
			return procModule.modBaseAddr;
		}
	}
	return NULL;
}

vector<proc::ModuleExport> proc::getModuleExports(HANDLE process, DWORD processId, const wchar_t* moduleName) {
	vector<proc::ModuleExport> moduleExports;
	auto moduleOpt = proc::getModule(processId, moduleName);

	if (!moduleOpt.has_value())
		return moduleExports;

	auto module = moduleOpt.value();

	auto moduleBase = module.hModule;
	auto dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
	auto ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)moduleBase + dosHeader->e_lfanew);
	auto optHeader = ntHeader->OptionalHeader;
	auto eatDir = optHeader.DataDirectory[0];
	auto eat = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)moduleBase + eatDir.VirtualAddress);
	auto names = (PDWORD) ((DWORD_PTR)moduleBase + eat->AddressOfNames);
	auto ordinals = (PWORD)((DWORD_PTR)moduleBase + eat->AddressOfNameOrdinals);
	auto functions = (PWORD)((DWORD_PTR)moduleBase + eat->AddressOfFunctions);

	for (size_t i = 0; i < eat->NumberOfNames; i++)
	{
		LPCSTR name = (LPCSTR)((DWORD_PTR)moduleBase + names[i]);
		WORD ordinal = (WORD)(ordinals[i]);
		PVOID function = (PVOID)((DWORD_PTR)moduleBase + functions[ordinal]);
		moduleExports.push_back(
			proc::ModuleExport {
				name,
				ordinal,
				function
			}
		);

	}
	
	return moduleExports;
}
vector<MEMORY_BASIC_INFORMATION> mem::getMemoryRegions(HANDLE process) {
	vector<MEMORY_BASIC_INFORMATION> regions;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	PVOID baseAddress = NULL;

	while (NT_SUCCESS(Sw3NtQueryVirtualMemory(process, baseAddress, MemoryBasicInformation, (PVOID)&mbi, sizeof(mbi), NULL))) {

		if (mbi.BaseAddress && mbi.State == MEM_COMMIT) {
			regions.push_back(mbi);
		}

		baseAddress = (PVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
	}

	return regions;
}

PVOID mem::rawReadMemory(HANDLE process, PVOID baseAddress, SIZE_T size) {
	PVOID readBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
	NTSTATUS ok = Sw3NtReadVirtualMemory(process, baseAddress, readBuffer, size, NULL);
	return readBuffer;
}
