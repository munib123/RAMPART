# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 392_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `392_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 127-166 of the vulnerable file.

		return false;
	}
}

inline bool loadBinaryModuleFromFile(const char* filename,
									 IR::Module& outModule,
									 Log::Category errorCategory = Log::error)
{
	std::vector<U8> wasmBytes;
	if(!loadFile(filename, wasmBytes)) { return false; }
	return loadBinaryModule(wasmBytes.data(), wasmBytes.size(), outModule);
}

inline bool loadModule(const char* filename, IR::Module& outModule)
{
	// Read the specified file into an array.
	std::vector<U8> fileBytes;
	if(!loadFile(filename, fileBytes)) { return false; }

	// If the file starts with the WASM binary magic number, load it as a binary irModule.
	if(*(U32*)fileBytes.data() == 0x6d736100)
	{ return loadBinaryModule(fileBytes.data(), fileBytes.size(), outModule); }
	else
	{
		// Make sure the WAST file is null terminated.
		fileBytes.push_back(0);

		// Load it as a text irModule.
		std::vector<WAST::Error> parseErrors;
		if(!WAST::parseModule(
			   (const char*)fileBytes.data(), fileBytes.size(), outModule, parseErrors))
		{
			Log::printf(Log::error, "Error parsing WebAssembly text file:\n");
			reportParseErrors(filename, parseErrors);
			return false;
		}

		return true;
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -144,7 +144,7 @@
 	if(!loadFile(filename, fileBytes)) { return false; }
 
 	// If the file starts with the WASM binary magic number, load it as a binary irModule.
-	if(*(U32*)fileBytes.data() == 0x6d736100)
+	if(fileBytes.size() >= 4 && *(U32*)fileBytes.data() == 0x6d736100)
 	{ return loadBinaryModule(fileBytes.data(), fileBytes.size(), outModule); }
 	else
 	{
```
