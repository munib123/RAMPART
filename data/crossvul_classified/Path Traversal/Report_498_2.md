# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 498_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `498_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 1-24 of the vulnerable file.

package cc.mrbird.common.handler;

import cc.mrbird.common.domain.ResponseBo;
import cc.mrbird.common.exception.LimitAccessException;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.session.ExpiredSessionException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;

@RestControllerAdvice
@Order(value = Ordered.HIGHEST_PRECEDENCE)
public class GlobalExceptionHandler {

    @ExceptionHandler(value = AuthorizationException.class)
    public Object handleAuthorizationException(HttpServletRequest request) {
        if (isAjaxRequest(request)) {
            return ResponseBo.error("暂无权限，请联系管理员！");
        } else {
            ModelAndView mav = new ModelAndView();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,7 @@
 package cc.mrbird.common.handler;
 
 import cc.mrbird.common.domain.ResponseBo;
+import cc.mrbird.common.exception.FileDownloadException;
 import cc.mrbird.common.exception.LimitAccessException;
 import org.apache.shiro.authz.AuthorizationException;
 import org.apache.shiro.session.ExpiredSessionException;
@@ -37,6 +38,11 @@
         return ResponseBo.error(e.getMessage());
     }
 
+    @ExceptionHandler(value = FileDownloadException.class)
+    public ResponseBo handleFileDownloadException(FileDownloadException e) {
+        return ResponseBo.error(e.getMessage());
+    }
+
     private static boolean isAjaxRequest(HttpServletRequest request) {
         return (request.getHeader("X-Requested-With") != null
                 && "XMLHttpRequest".equals(request.getHeader("X-Requested-With")));
```
