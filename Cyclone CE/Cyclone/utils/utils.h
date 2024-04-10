#pragma once
#include "../engine/Syscalls/Syscalls.h"
#include<iostream>
namespace utils {
	
	void doUUIDShit();
}

void utils::doUUIDShit() {
	ULONG infoLength = 0;
	Sw3NtQuerySystemInformation(
		SystemFirmwareTableInformation,
		NULL,
		0,
		&infoLength
	);
	printf("%lu\n", infoLength);

	PVOID fwInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, infoLength);

	NTSTATUS okQ = Sw3NtQuerySystemInformation(
		SystemFirmwareTableInformation,
		fwInfo,
		infoLength,
		&infoLength
	);
	printf("%x\n", okQ);
}