# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 393_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `393_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 233-274 of the vulnerable file.

		}
	}
	else
	{
		functionInstance
			= asFunctionNullable(getInstanceExport(moduleInstance, options.functionName));
		if(!functionInstance)
		{
			Log::printf(Log::error, "Module does not export '%s'\n", options.functionName);
			return EXIT_FAILURE;
		}
	}
	FunctionType functionType = getFunctionType(functionInstance);

	// Set up the arguments for the invoke.
	std::vector<Value> invokeArgs;
	if(!options.functionName)
	{
		if(functionType.params().size() == 2)
		{
			MemoryInstance* defaultMemory = Runtime::getDefaultMemory(moduleInstance);
			if(!defaultMemory)
			{
				Log::printf(
					Log::error,
					"Module does not declare a default memory object to put arguments in.\n");
				return EXIT_FAILURE;
			}

			std::vector<const char*> argStrings;
			argStrings.push_back(options.filename);
			char** args = options.args;
			while(*args) { argStrings.push_back(*args++); };

			Emscripten::injectCommandArgs(emscriptenInstance, argStrings, invokeArgs);
		}
		else if(functionType.params().size() > 0)
		{
			Log::printf(Log::error,
						"WebAssembly function requires %" PRIu64
						" argument(s), but only 0 or 2 can be passed!",
						functionType.params().size());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -250,21 +250,23 @@
 	{
 		if(functionType.params().size() == 2)
 		{
-			MemoryInstance* defaultMemory = Runtime::getDefaultMemory(moduleInstance);
-			if(!defaultMemory)
+			if(!emscriptenInstance)
 			{
 				Log::printf(
 					Log::error,
 					"Module does not declare a default memory object to put arguments in.\n");
 				return EXIT_FAILURE;
 			}
-
-			std::vector<const char*> argStrings;
-			argStrings.push_back(options.filename);
-			char** args = options.args;
-			while(*args) { argStrings.push_back(*args++); };
-
-			Emscripten::injectCommandArgs(emscriptenInstance, argStrings, invokeArgs);
+			else
+			{
+				std::vector<const char*> argStrings;
+				argStrings.push_back(options.filename);
+				char** args = options.args;
+				while(*args) { argStrings.push_back(*args++); };
+
+				wavmAssert(emscriptenInstance);
+				Emscripten::injectCommandArgs(emscriptenInstance, argStrings, invokeArgs);
+			}
 		}
 		else if(functionType.params().size() > 0)
 		{
```
