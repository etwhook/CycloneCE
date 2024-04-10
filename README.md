
# 🏓 Cyclone CE

Cyclone UM Native Cheat Engine, Work In Progress.

## 👁 Examples

```cpp
	auto processId = engine::proc::getProcId(L"notepad.exe");
	auto process = engine::proc::openProcess(processId);
	if (!processId)
		return -1;

	auto exports = engine::proc::getModuleExports(process, processId, L"ntdll.dll");

	for (auto& mExport : exports) {
		printf("%s -> %p\n", mExport.name, mExport.functionVA);
	}

...
```
