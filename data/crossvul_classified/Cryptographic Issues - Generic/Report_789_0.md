# CrossVul Fix Pair: Cryptographic Issues in java
**Pair ID:** 789_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `789_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```java
Lines 1-27 of the vulnerable file.

package org.airsonic.player.controller;

import de.triology.recaptchav2java.ReCaptcha;
import org.airsonic.player.domain.User;
import org.airsonic.player.service.SecurityService;
import org.airsonic.player.service.SettingsService;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,6 @@
 import org.airsonic.player.domain.User;
 import org.airsonic.player.service.SecurityService;
 import org.airsonic.player.service.SettingsService;
-import org.apache.commons.lang.RandomStringUtils;
 import org.apache.commons.lang.StringUtils;
 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;
@@ -22,6 +21,7 @@
 import javax.servlet.http.HttpServletRequest;
 import javax.servlet.http.HttpServletResponse;
 
+import java.security.SecureRandom;
 import java.util.Date;
 import java.util.HashMap;
 import java.util.Map;
@@ -36,6 +36,10 @@
 
 
     private static final Logger LOG = LoggerFactory.getLogger(RecoverController.class);
+
+    private static final String SYMBOLS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
+    private final SecureRandom random = new SecureRandom();
+    private static final int PASSWORD_LENGTH = 32;
 
     @Autowired
     private SettingsService settingsService;
@@ -69,7 +73,13 @@
             } else if (user.getEmail() == null) {
                 map.put("error", "recover.error.noemail");
             } else {
-                String password = RandomStringUtils.randomAlphanumeric(8);
+                StringBuilder sb = new StringBuilder(PASSWORD_LENGTH);
+                for(int i=0; i<PASSWORD_LENGTH; i++) {
+                  int index = random.nextInt(SYMBOLS.length());
+                  sb.append(SYMBOLS.charAt(index));
+                }
+                String password = sb.toString();
+
                 if (emailPassword(password, user.getUsername(), user.getEmail())) {
                     map.put("sentTo", user.getEmail());
                     user.setLdapAuthenticated(false);
```
