# CrossVul Fix Pair: Improper Input Validation in typescript
**Pair ID:** 2477_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2477_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```typescript
Lines 58-99 of the vulnerable file.


		Object.assign(configuration[configProperty], config[configProperty] || {});
	}
}

export function applyCommandArgs(configuration: any, argv: string[]) {
	if (!argv || !argv.length) {
		return;
	}

	argv = argv.slice(2);

	const parsedArgv = yargs(argv);
	const argvKeys = Object.keys(parsedArgv);
	if (!argvKeys.length) {
		return;
	}

	debug("Appling command arguments:", parsedArgv);

	if (parsedArgv.config) {
		const configFile = path.resolve(process.cwd(), parsedArgv.config);
		applyConfigFile(configuration, configFile);
	}

	for (const key in parsedArgv) {
		if (!parsedArgv.hasOwnProperty(key)) {
			continue;
		}

		const configKey = key
			.replace(/_/g, ".");

		debug(`Found config value from cmd args '${key}' to '${configKey}'`);

		setDeepProperty(configuration, configKey, parsedArgv[key]);
	}
}


export function setDeepProperty(obj: any, propertyPath: string, value: any): void {
	const a = splitPath(propertyPath);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,8 +75,10 @@
 
 	debug("Appling command arguments:", parsedArgv);
 
-	if (parsedArgv.config) {
-		const configFile = path.resolve(process.cwd(), parsedArgv.config);
+	const CONFIG_PROP = 'config';
+
+	if (parsedArgv[CONFIG_PROP]) {
+		const configFile = path.resolve(process.cwd(), parsedArgv[CONFIG_PROP]);
 		applyConfigFile(configuration, configFile);
 	}
 
@@ -85,6 +87,16 @@
 			continue;
 		}
 
+		if (key.startsWith('_')) {
+			continue;
+		}
+		if (key.endsWith('_')) {
+			continue;
+		}
+		if (key === CONFIG_PROP) {
+			continue;
+		}
+
 		const configKey = key
 			.replace(/_/g, ".");
 
@@ -95,22 +107,42 @@
 }
 
 
-export function setDeepProperty(obj: any, propertyPath: string, value: any): void {
-	const a = splitPath(propertyPath);
-	const n = a.length;
-
-	for (let i = 0; i < n - 1; i++) {
-		const k = a[i];
-
-		if (!(k in obj)) {
-			obj[k] = {};
-		}
-		obj = obj[k];
-	}
-
-
-	obj[a[n - 1]] = value;
+export function setDeepProperty(obj: {[key: string]: any}, propertyPath: string, value: any): void {
+	if (!obj) {
+		throw new Error("Invalid object");
+	}
+	if (!propertyPath) {
+		throw new Error("Invalid property path");
+	}
+
+	const pathParts = splitPath(propertyPath);
+	const pathPartsLen = pathParts.length;
+
+	for (let i = 0; i < pathPartsLen - 1; i++) {
+		const pathPart = pathParts[i];
+
+		if (!(pathPart in obj)) {
+			setProp(obj, pathPart, {});
+		}
+		obj = getProp(obj, pathPart);
+	}
+
+	setProp(obj, pathParts[pathPartsLen - 1], value);
 	return;
+}
+
+function setProp(obj: {[key: string]: any}, property: string, value: any): void {
+	if (!obj.hasOwnProperty(property)) {
+		throw new Error(`Property '${property}' is not valid`);
+	}
+	obj[property] = value;
+}
+
+function getProp(obj: {[key: string]: any}, property: string): any {
+	if (!obj.hasOwnProperty(property)) {
+		throw new Error(`Property '${property}' is not valid`);
+	}
+	return obj[property];
 }
 
 export function getDeepProperty(obj: any, propertyPath: string): any {
```
