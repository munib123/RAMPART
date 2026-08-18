# CrossVul Fix Pair: Improperly Controlled Modification of Dynamically-Determined Object Attributes in typescript
**Pair ID:** 1938_0
**Vulnerability Class:** Modification of Assumed-Immutable Data (MAID)
**CWE:** CWE-915
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1938_0`)

## Vulnerability Information & PoC

## Description
Improperly Controlled Modification of Dynamically-Determined Object Attributes - If the object contains attributes that were only intended for internal use, then their unexpected modification could lead to a vulnerability.

## Vulnerable Code
```typescript
Lines 1-21 of the vulnerable file.

import {GeneralObject, GeneralObjectOrValue} from "./types";

export = <T>(object: GeneralObject<T>, key: string, value: any): GeneralObject<T> => {
	const keyParts = key.split(".");
	let objectRef: GeneralObjectOrValue<T> = object;
	keyParts.forEach((part: string | number, index: number) => {
		if (keyParts.length - 1 === index) {
			return;
		}

		if (!objectRef[part]) {
			objectRef[part] = {};
		}

		objectRef = objectRef[part];
	});

	objectRef[keyParts[keyParts.length - 1]] = value;

	return object;
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,7 +15,10 @@
 		objectRef = objectRef[part];
 	});
 
-	objectRef[keyParts[keyParts.length - 1]] = value;
+	const finalKey: string = keyParts[keyParts.length - 1];
+	if (finalKey !== "__proto__" && finalKey !== "constructor") {
+		objectRef[finalKey] = value;
+	}
 
 	return object;
 };
```
