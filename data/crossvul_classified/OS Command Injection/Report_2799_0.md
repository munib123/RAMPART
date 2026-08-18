# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in cpp
**Pair ID:** 2799_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2799_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```cpp
Lines 289-318 of the vulnerable file.

			--dl2start;
		}
	}
}

void pb_controller::increase_parallel_downloads() {
	++max_dls;
}

void pb_controller::decrease_parallel_downloads() {
	if (max_dls > 1)
		--max_dls;
}

void pb_controller::play_file(const std::string& file) {
	std::string cmdline;
	std::string player = cfg->get_configvalue("player");
	if (player == "")
		return;
	cmdline.append(player);
	cmdline.append(" \"");
	cmdline.append(utils::replace_all(file,"\"", "\\\""));
	cmdline.append("\"");
	stfl::reset();
	LOG(LOG_DEBUG, "pb_controller::play_file: running `%s'", cmdline.c_str());
	::system(cmdline.c_str());
}


} // namespace
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -306,9 +306,9 @@
 	if (player == "")
 		return;
 	cmdline.append(player);
-	cmdline.append(" \"");
-	cmdline.append(utils::replace_all(file,"\"", "\\\""));
-	cmdline.append("\"");
+	cmdline.append(" \'");
+	cmdline.append(utils::replace_all(file,"'", "%27"));
+	cmdline.append("\'");
 	stfl::reset();
 	LOG(LOG_DEBUG, "pb_controller::play_file: running `%s'", cmdline.c_str());
 	::system(cmdline.c_str());
```
