# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 4348_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4348_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```java
Lines 1-33 of the vulnerable file.

/*
 * Copyright (c) 2020 Ubique Innovation AG <https://www.ubique.ch>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
package org.dpppt.backend.sdk.ws.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.Jwts;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.dpppt.backend.sdk.data.gaen.FakeKeyService;
import org.dpppt.backend.sdk.data.gaen.GAENDataService;
import org.dpppt.backend.sdk.model.gaen.*;
import org.dpppt.backend.sdk.ws.radarcovid.annotation.Loggable;
import org.dpppt.backend.sdk.ws.security.ValidateRequest;
import org.dpppt.backend.sdk.ws.security.ValidateRequest.InvalidDateException;
import org.dpppt.backend.sdk.ws.security.signature.ProtoSignature;
import org.dpppt.backend.sdk.ws.security.signature.ProtoSignature.ProtoSignatureWrapper;
import org.dpppt.backend.sdk.ws.util.ValidationUtils;
import org.dpppt.backend.sdk.ws.util.ValidationUtils.BadBatchReleaseTimeException;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.slf4j.Logger;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,7 @@
 package org.dpppt.backend.sdk.ws.controller;
 
 import com.fasterxml.jackson.core.JsonProcessingException;
+
 import io.jsonwebtoken.Jwts;
 import io.swagger.v3.oas.annotations.Operation;
 import io.swagger.v3.oas.annotations.Parameter;
@@ -20,6 +21,7 @@
 import org.dpppt.backend.sdk.data.gaen.GAENDataService;
 import org.dpppt.backend.sdk.model.gaen.*;
 import org.dpppt.backend.sdk.ws.radarcovid.annotation.Loggable;
+import org.dpppt.backend.sdk.ws.radarcovid.annotation.ResponseRetention;
 import org.dpppt.backend.sdk.ws.security.ValidateRequest;
 import org.dpppt.backend.sdk.ws.security.ValidateRequest.InvalidDateException;
 import org.dpppt.backend.sdk.ws.security.signature.ProtoSignature;
@@ -100,6 +102,7 @@
 
 	@PostMapping(value = "/exposed")
 	@Loggable
+	@ResponseRetention(time = "application.response.retention.time.exposed")
 	@Transactional
 	@Operation(description = "Send exposed keys to server - includes a fix for the fact that GAEN doesn't give access to the current day's exposed key")
 	@ApiResponses(value = {
```
