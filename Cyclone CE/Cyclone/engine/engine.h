#pragma once
#include<windows.h>
#include<TlHelp32.h>
#include<vector>
#include "./Syscalls/Syscalls.h"
#include<optional>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

using std::vector;

namespace engine {

	namespace proc {
		class ModuleExport {
		public:
			LPCSTR name;
			WORD ordinal;
			PVOID functionVA;
		};

		HANDLE openProcess(DWORD processId);
		HANDLE openThread(DWORD threadId);

		vector<SYSTEM_THREAD_INFORMATION> getProcThreadsInfo(DWORD processId);
		vector<HANDLE> getProcThreads(DWORD processId);
		bool suspendThread(HANDLE thread);
		bool resumeThread(HANDLE thread);

		vector<RTL_PROCESS_MODULE_INFORMATION> getKernelModulesInfo();
		vector<MODULEENTRY32W> getProcModulesInfo(DWORD processId);

		DWORD getProcId(const wchar_t* targetProcessName);
		
		PVOID getModuleBase(DWORD processId, const wchar_t* moduleName);
		std::optional<MODULEENTRY32W> getModule(DWORD processId, const wchar_t* moduleName);
		vector<proc::ModuleExport> getModuleExports(HANDLE process, DWORD processId, const wchar_t* moduleName);
	}
	namespace mem {

		LPVOID allocHeap(SIZE_T memSize);
		bool freeHeap(LPVOID mem);

		vector<MEMORY_BASIC_INFORMATION> getMemoryRegions(HANDLE process);

		template<typename T>
		T readMemory(HANDLE process, PVOID baseAddress) {
			PVOID readBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(T));
			Sw3NtReadVirtualMemory(process, baseAddress, readBuffer, sizeof(T), NULL);
			return *reinterpret_cast<T*>(readBuffer);
		}

		PVOID rawReadMemory(HANDLE process, PVOID baseAddress, SIZE_T size);

		template<typename T>
		bool writeMemory(HANDLE process, PVOID baseAddress, T writeBuffer) {
			NTSTATUS okWrite = Sw3NtWriteVirtualMemory(
				process,
				baseAddress,
				(PVOID)&writeBuffer,
				sizeof(T),
				NULL
			);
			return NT_SUCCESS(
				okWrite
			);
		}
		template <typename T>
		vector<PVOID> findValuesInMemory(HANDLE process, T value) {
			vector<PVOID> foundRegionValues;
			auto regions = getMemoryRegions(process);
			for (auto& region : regions) {
				auto regionAddress = region.BaseAddress;
				auto regionData = rawReadMemory(process, regionAddress, region.RegionSize);			
				
				for (size_t i = 0; i <= region.RegionSize - sizeof(T); i += sizeof(T))
				{
					T readVal = *(T*)((DWORD_PTR)regionData + i);
					if (!readVal)
						continue;

					if (readVal == value) {
						foundRegionValues.push_back(
						reinterpret_cast<PVOID>((DWORD_PTR)regionData + i)
						);
					}
				}

				mem::freeHeap(regionData);
			}
			return foundRegionValues;
		}

	}


}
