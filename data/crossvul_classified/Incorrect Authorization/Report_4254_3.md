# CrossVul Fix Pair: Incorrect Authorization in java
**Pair ID:** 4254_3
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4254_3`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```java
Lines 1-33 of the vulnerable file.

package com.zrlog.web.handler;

import com.hibegin.common.util.IOUtil;
import com.hibegin.common.util.http.HttpUtil;
import com.hibegin.common.util.http.handle.CloseResponseHandle;
import com.jfinal.core.JFinal;
import com.jfinal.handler.Handler;
import com.zrlog.common.Constants;
import com.zrlog.common.vo.AdminTokenVO;
import com.zrlog.model.User;
import com.zrlog.service.AdminTokenService;
import com.zrlog.service.AdminTokenThreadLocal;
import com.zrlog.service.PluginHelper;
import com.zrlog.util.BlogBuildInfoUtil;
import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.log4j.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 这个类负责了对所有的插件路由的代理中转给插件服务（及plugin-core.jar这个进程），使用的是Handler而非Interception也是由于Interception
 * 不处理静态请求。
 * 目前插件服务拦截了
 * 1./admin/plugins/* （进行权限检查）
 * 2./plugin/* /p/* （是plugin的短路由，代码逻辑上是不区分的，不检查权限）
 * <p>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,8 +10,8 @@
 import com.zrlog.model.User;
 import com.zrlog.service.AdminTokenService;
 import com.zrlog.service.AdminTokenThreadLocal;
-import com.zrlog.service.PluginHelper;
 import com.zrlog.util.BlogBuildInfoUtil;
+import com.zrlog.web.util.PluginHelper;
 import org.apache.http.Header;
 import org.apache.http.client.methods.CloseableHttpResponse;
 import org.apache.log4j.Logger;
@@ -52,8 +52,9 @@
             }
         }
         if (isPluginPath) {
+            Map.Entry<AdminTokenVO, User> entry = null;
             try {
-                Map.Entry<AdminTokenVO, User> entry = adminTokenService.getAdminTokenVOUserEntry(request);
+                entry = adminTokenService.getAdminTokenVOUserEntry(request);
                 if (entry != null) {
                     adminTokenService.setAdminToken(entry.getValue(), entry.getKey().getSessionId(), entry.getKey().getProtocol(), request, response);
                 }
@@ -72,6 +73,9 @@
                 }
             } finally {
                 isHandled[0] = true;
+                if (entry != null) {
+                    AdminTokenThreadLocal.remove();
+                }
             }
         } else {
             this.next.handle(target, request, response, isHandled);
@@ -153,13 +157,13 @@
         HttpUtil httpUtil = disableRedirect ? HttpUtil.getDisableRedirectInstance() : HttpUtil.getInstance();
         //GET请求不关心request.getInputStream() 的数据
         if (method.equals(request.getMethod()) && "GET".equalsIgnoreCase(method)) {
-            httpResponse = httpUtil.sendGetRequest(pluginServerHttp + uri, request.getParameterMap(), handle, PluginHelper.genHeaderMapByRequest(request)).getT();
+            httpResponse = httpUtil.sendGetRequest(pluginServerHttp + uri, request.getParameterMap(), handle, PluginHelper.genHeaderMapByRequest(request, AdminTokenThreadLocal.getUser())).getT();
         } else {
             //如果是表单数据提交不关心请求头，反之将所有请求头都发到插件服务
             if ("application/x-www-form-urlencoded".equals(request.getContentType())) {
-                httpResponse = httpUtil.sendPostRequest(pluginServerHttp + uri, request.getParameterMap(), handle, PluginHelper.genHeaderMapByRequest(request)).getT();
+                httpResponse = httpUtil.sendPostRequest(pluginServerHttp + uri, request.getParameterMap(), handle, PluginHelper.genHeaderMapByRequest(request, AdminTokenThreadLocal.getUser())).getT();
             } else {
-                httpResponse = httpUtil.sendPostRequest(pluginServerHttp + uri + "?" + request.getQueryString(), IOUtil.getByteByInputStream(request.getInputStream()), handle, PluginHelper.genHeaderMapByRequest(request)).getT();
+                httpResponse = httpUtil.sendPostRequest(pluginServerHttp + uri + "?" + request.getQueryString(), IOUtil.getByteByInputStream(request.getInputStream()), handle, PluginHelper.genHeaderMapByRequest(request, AdminTokenThreadLocal.getUser())).getT();
             }
         }
         //添加插件服务的HTTP响应头到调用者响应头里面
```
