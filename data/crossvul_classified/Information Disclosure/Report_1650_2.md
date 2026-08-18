# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 1650_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1650_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 991-1031 of the vulnerable file.

}

std::string get_wml_location(const std::string &filename, const std::string &current_dir)
{
	DBG_FS << "Looking for '" << filename << "'." << std::endl;

	assert(game_config::path.empty() == false);

	std::string result;

	if (filename.empty()) {
		LOG_FS << "  invalid filename" << std::endl;
		return result;
	}

	if (filename.find("..") != std::string::npos) {
		ERR_FS << "Illegal path '" << filename << "' (\"..\" not allowed)." << std::endl;
		return result;
	}

	if (ends_with(filename, ".pbl")) {
		ERR_FS << "Illegal path '" << filename << "' (.pbl files are not allowed)." << std::endl;
		return result;
	}

	bool already_found = false;

	if (filename[0] == '~')
	{
		// If the filename starts with '~', look in the user data directory.
		result = get_user_data_dir() + "/data/" + filename.substr(1);
		DBG_FS << "  trying '" << result << "'" << std::endl;

		already_found = file_exists(result) || is_directory(result);
	}
	else if (filename.size() >= 2 && filename[0] == '.' && filename[1] == '/')
	{
		// If the filename begins with a "./", look in the same directory
		// as the file currently being preprocessed.

		if (!current_dir.empty())
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1008,7 +1008,7 @@
 		return result;
 	}
 
-	if (ends_with(filename, ".pbl")) {
+	if (looks_like_pbl(filename)) {
 		ERR_FS << "Illegal path '" << filename << "' (.pbl files are not allowed)." << std::endl;
 		return result;
 	}
```
