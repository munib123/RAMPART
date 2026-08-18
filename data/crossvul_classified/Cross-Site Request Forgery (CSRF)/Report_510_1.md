# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 510_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `510_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 3-43 of the vulnerable file.

 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 */

package org.hswebframework.web.authorization.oauth2.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.hswebframework.web.WebUtil;
import org.hswebframework.web.authorization.oauth2.client.OAuth2RequestService;
import org.hswebframework.web.authorization.oauth2.client.listener.OAuth2CodeAuthBeforeEvent;
import org.hswebframework.web.controller.message.ResponseMessage;
import org.hswebframework.web.entity.oauth2.client.OAuth2ServerConfigEntity;
import org.hswebframework.web.id.IDGenerator;
import org.hswebframework.web.oauth2.core.OAuth2Constants;
import org.hswebframework.web.service.oauth2.client.OAuth2ServerConfigService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;

/**
 * @author zhouhao
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,12 +20,14 @@
 
 import io.swagger.annotations.Api;
 import io.swagger.annotations.ApiOperation;
+import org.hswebframework.web.BusinessException;
 import org.hswebframework.web.WebUtil;
 import org.hswebframework.web.authorization.oauth2.client.OAuth2RequestService;
 import org.hswebframework.web.authorization.oauth2.client.listener.OAuth2CodeAuthBeforeEvent;
 import org.hswebframework.web.controller.message.ResponseMessage;
 import org.hswebframework.web.entity.oauth2.client.OAuth2ServerConfigEntity;
 import org.hswebframework.web.id.IDGenerator;
+import org.hswebframework.web.oauth2.core.ErrorType;
 import org.hswebframework.web.oauth2.core.OAuth2Constants;
 import org.hswebframework.web.service.oauth2.client.OAuth2ServerConfigService;
 import org.springframework.beans.factory.annotation.Autowired;
@@ -104,7 +106,9 @@
                                  HttpSession session) throws UnsupportedEncodingException {
         try {
             String cachedState = (String) session.getAttribute(STATE_SESSION_KEY);
-            //  if (!state.equals(cachedState)) throw new BusinessException("state error");
+            if (!state.equals(cachedState)) {
+                throw new BusinessException(ErrorType.STATE_ERROR.name());
+            }
             oAuth2RequestService.doEvent(serverId, new OAuth2CodeAuthBeforeEvent(code, state, request::getParameter));
             return new RedirectView(URLDecoder.decode(redirect, "UTF-8"));
         } finally {
```
