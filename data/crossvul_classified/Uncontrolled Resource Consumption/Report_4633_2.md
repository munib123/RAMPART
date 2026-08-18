# CrossVul Fix Pair: Uncontrolled Resource Consumption in typescript
**Pair ID:** 4633_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4633_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```typescript
Lines 1-21 of the vulnerable file.

import {getClass, isArrayOrArrayClass, isEmpty, isPrimitiveOrPrimitiveClass, Metadata, Type} from "@tsed/core";
import {Configuration, Injectable, InjectorService} from "@tsed/di";
import {IConverterSettings} from "../../config/interfaces/IConverterSettings";
import {PropertyMetadata} from "../../mvc/models/PropertyMetadata";
import {getJsonSchema} from "../../jsonschema/utils/getJsonSchema";
import {ArrayConverter, DateConverter, MapConverter, PrimitiveConverter, SetConverter, SymbolConverter} from "../components";
import {CONVERTER} from "../constants/index";
import {RequiredPropertyError} from "../errors/RequiredPropertyError";
import {UnknownPropertyError} from "../errors/UnknownPropertyError";
import {IConverter, IConverterOptions, IDeserializer, ISerializer} from "../interfaces/index";

@Injectable({
  imports: [ArrayConverter, DateConverter, MapConverter, PrimitiveConverter, SetConverter, SymbolConverter]
})
export class ConverterService {
  private converterSettings: IConverterSettings;

  constructor(private injectorService: InjectorService, @Configuration() configuration: Configuration) {
    this.converterSettings = configuration.get<IConverterSettings>("converter") || {};

    if (this.converterSettings.additionalProperties === undefined) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-import {getClass, isArrayOrArrayClass, isEmpty, isPrimitiveOrPrimitiveClass, Metadata, Type} from "@tsed/core";
+import {getClass, isArrayOrArrayClass, isEmpty, isPrimitiveOrPrimitiveClass, Metadata, objectKeys, Type} from "@tsed/core";
 import {Configuration, Injectable, InjectorService} from "@tsed/di";
 import {IConverterSettings} from "../../config/interfaces/IConverterSettings";
 import {PropertyMetadata} from "../../mvc/models/PropertyMetadata";
@@ -101,7 +101,7 @@
 
     const plainObject: any = {};
     const properties = PropertyMetadata.getProperties(options.type || obj, {withIgnoredProps});
-    const keys = properties.size ? Array.from(properties.keys()) : Object.keys(obj);
+    const keys = properties.size ? Array.from(properties.keys()) : objectKeys(obj);
 
     keys.forEach((propertyKey) => {
       if (typeof obj[propertyKey] !== "function") {
@@ -179,7 +179,7 @@
     const instance = new targetType();
     const properties = PropertyMetadata.getProperties(targetType);
 
-    Object.keys(obj).forEach((propertyName: string) => {
+    objectKeys(obj).forEach((propertyName: string) => {
       const propertyMetadata = ConverterService.getPropertyMetadata(properties, propertyName);
 
       return this.convertProperty(obj, instance, propertyName, propertyMetadata, options);
```
