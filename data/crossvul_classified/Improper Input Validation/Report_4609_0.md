# CrossVul Fix Pair: Improper Input Validation in typescript
**Pair ID:** 4609_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4609_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```typescript
Lines 128-168 of the vulnerable file.


            if (this.options.enableCircularCheck) {
                // add transformed type to prevent circular references
                this.recursionStack.add(value);
            }

            const keys = this.getKeys((targetType as Function), value);
            let newValue: any = source ? source : {};
            if (!source && (this.transformationType === TransformationType.PLAIN_TO_CLASS || this.transformationType === TransformationType.CLASS_TO_CLASS)) {
                if (isMap) {
                    newValue = new Map();
                } else if (targetType) {
                    newValue = new (targetType as any)();
                } else {
                    newValue = {};
                }
            }

            // traverse over keys
            for (const key of keys) {
                const valueKey = key;
                let newValueKey = key, propertyName = key;
                if (!this.options.ignoreDecorators && targetType) {
                    if (this.transformationType === TransformationType.PLAIN_TO_CLASS) {
                        const exposeMetadata = defaultMetadataStorage.findExposeMetadataByCustomName((targetType as Function), key);
                        if (exposeMetadata) {
                            propertyName = exposeMetadata.propertyName;
                            newValueKey = exposeMetadata.propertyName;
                        }

                    } else if (this.transformationType === TransformationType.CLASS_TO_PLAIN || this.transformationType === TransformationType.CLASS_TO_CLASS) {
                        const exposeMetadata = defaultMetadataStorage.findExposeMetadata((targetType as Function), key);
                        if (exposeMetadata && exposeMetadata.options && exposeMetadata.options.name) {
                            newValueKey = exposeMetadata.options.name;
                        }
                    }
                }

                // get a subvalue
                let subValue: any = undefined;
                if (value instanceof Map) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -145,6 +145,10 @@
 
             // traverse over keys
             for (const key of keys) {
+                if (key === '__proto__' || key === 'constructor') {
+                    continue;
+                }
+
                 const valueKey = key;
                 let newValueKey = key, propertyName = key;
                 if (!this.options.ignoreDecorators && targetType) {
```
