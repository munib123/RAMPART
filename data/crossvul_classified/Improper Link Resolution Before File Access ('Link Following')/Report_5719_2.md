# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in cpp
**Pair ID:** 5719_2
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5719_2`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```cpp
Lines 41-81 of the vulnerable file.

		{
			ServerInstanceDir dir(parentDir + "/passenger-test.1234");
		}
		ensure_equals(listDir(parentDir).size(), 0u);
		
		{
			ServerInstanceDir dir(parentDir + "/passenger-test.1234");
			createGenerationDir(dir.getPath(), 1);
		}
		ensure_equals(listDir(parentDir).size(), 1u);
	}
	
	TEST_METHOD(4) {
		// The destructor does not throw any exceptions if the server instance
		// directory doesn't exist anymore.
		ServerInstanceDir dir(parentDir + "/passenger-test.1234");
		removeDirTree(dir.getPath());
	}
	
	TEST_METHOD(5) {
		// The destructor doesnn't remove the server instance directory if it
		// wasn't created with the ownership flag or if it's been detached.
		string path, path2;
		{
			ServerInstanceDir dir(parentDir + "/passenger-test.1234", false);
			ServerInstanceDir dir2(parentDir + "/passenger-test.5678", false);
			dir2.detach();
			path = dir.getPath();
			path2 = dir2.getPath();
		}
		ensure_equals(getFileType(path), FT_DIRECTORY);
		ensure_equals(getFileType(path2), FT_DIRECTORY);
	}
	
	TEST_METHOD(6) {
		// If there are no existing generations, newGeneration() creates a new
		// generation directory with number 0.
		ServerInstanceDir dir(parentDir + "/passenger-test.1234");
		unsigned int ncontents = listDir(dir.getPath()).size();
		ServerInstanceDir::GenerationPtr generation = dir.newGeneration(true,
			"nobody", nobodyGroup, 0, 0);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,9 +58,11 @@
 	}
 	
 	TEST_METHOD(5) {
-		// The destructor doesnn't remove the server instance directory if it
+		// The destructor doesn't remove the server instance directory if it
 		// wasn't created with the ownership flag or if it's been detached.
 		string path, path2;
+		makeDirTree(parentDir + "/passenger-test.1234");
+		makeDirTree(parentDir + "/passenger-test.5678");
 		{
 			ServerInstanceDir dir(parentDir + "/passenger-test.1234", false);
 			ServerInstanceDir dir2(parentDir + "/passenger-test.5678", false);
```
