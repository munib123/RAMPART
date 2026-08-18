# CrossVul Fix Pair: Improper Input Validation in typescript
**Pair ID:** 2477_6
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2477_6`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```typescript
Lines 1-21 of the vulnerable file.

import * as confinit from "../index";
import * as path from "path";

export class Section1Config implements confinit.IConfigSection {
	url: string = "";

	validate(): void {
		if (!this.url) {
			throw new Error("Section 1 url not set.");
		}
	}
}

export class WebServerConfig implements confinit.IConfigSection {
	port = 3000;

	constructor() {
		const envPort = process.env.PORT;
		if (envPort) {
			this.port = parseInt(envPort, 10);
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,5 @@
+// See README.md for details
+
 import * as confinit from "../index";
 import * as path from "path";
 
@@ -37,11 +39,15 @@
 		if (!env) {
 			env = process.env;
 		}
+
+		// Enable config file
 		if (env.config) {
 			const configFile = path.resolve(process.cwd(), env.config);
 			confinit.applyConfigFile(this, configFile);
 		}
+		// Enable environment variables
 		confinit.applyEnvVariables(this, process.env, "cfg_");
+		// Enable command arguments
 		confinit.applyCommandArgs(this, process.argv);
 
 		confinit.validate(this);
```
