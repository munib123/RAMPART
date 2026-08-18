# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 590_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `590_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 1-40 of the vulnerable file.

/*
 * Copyright 2013-present Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.facebook.buck.cli;

import com.facebook.buck.parser.ParserConfig;
import com.facebook.buck.parser.thrift.RemoteDaemonicParserState;
import com.facebook.buck.util.ExitCode;
import com.facebook.buck.util.json.ObjectMappers;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.Preconditions;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.annotation.Nullable;
import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.Option;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,6 +17,7 @@
 package com.facebook.buck.cli;
 
 import com.facebook.buck.parser.ParserConfig;
+import com.facebook.buck.parser.ParserStateObjectInputStream;
 import com.facebook.buck.parser.thrift.RemoteDaemonicParserState;
 import com.facebook.buck.util.ExitCode;
 import com.facebook.buck.util.json.ObjectMappers;
@@ -88,7 +89,7 @@
           ZipInputStream zipis = new ZipInputStream(fis)) {
         ZipEntry entry = zipis.getNextEntry();
         Preconditions.checkState(entry.getName().equals("parser_data"));
-        try (ObjectInputStream ois = new ObjectInputStream(zipis)) {
+        try (ObjectInputStream ois = new ParserStateObjectInputStream(zipis)) {
           RemoteDaemonicParserState state;
           try {
             state = (RemoteDaemonicParserState) ois.readObject();
```
