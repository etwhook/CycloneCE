#include<iostream>
#include "engine/engine.h"
#include "utils/utils.h"
int main() {
	/*
	* auto processId = engine::proc::getProcId(L"notepad.exe");
	auto process = engine::proc::openProcess(processId);
	if (!processId)
		return -1;

	auto exports = engine::proc::getModuleExports(process, processId, L"ntdll.dll");

	for (auto& mExport : exports) {
		printf("%s -> %p\n", mExport.name, mExport.functionVA);
	}
	*/
	utils::doUUIDShit();
}
