# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in java
**Pair ID:** 5029_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5029_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```java
Lines 92-132 of the vulnerable file.

		String captcha = request.getParameter("captcha");
		if (useCaptcha) {
		    Captcha captchaObj = (Captcha) session.getAttribute(Captcha.NAME);
            String captchaSession=captchaObj!=null ? captchaObj.getAnswer() : null;
            
			if(captcha ==null && Config.getBooleanProperty("FORCE_CAPTCHA",true)){
				response.getWriter().write("Captcha is required to submit this form ( FORCE_CAPTCHA=true ).<br>To change this, edit the dotmarketing-config.properties and set FORCE_CAPTCHA=false");
				return null;
			}
			
			
			if(!UtilMethods.isSet(captcha) || !UtilMethods.isSet(captchaSession) || !captcha.equals(captchaSession)) {
				errors.add(Globals.ERROR_KEY, new ActionMessage("message.contentlet.required", "Validation Image"));
				request.setAttribute(Globals.ERROR_KEY, errors);
				session.setAttribute(Globals.ERROR_KEY, errors);
				String queryString = request.getQueryString();
				String invalidCaptchaURL = request.getParameter("invalidCaptchaReturnUrl");
				if(!UtilMethods.isSet(invalidCaptchaURL)) {
					invalidCaptchaURL = errorURL;
				}
				ActionForward af = new ActionForward();
					af.setRedirect(true);
					if (UtilMethods.isSet(queryString)) {
						
						af.setPath(invalidCaptchaURL + "?" + queryString + "&error=Validation-Image");
					} else {
						af.setPath(invalidCaptchaURL + "?error=Validation-Image");
					}
			

				
				return af;
			}
			
		}



		Map<String, Object> parameters = null;
		if (request instanceof UploadServletRequest)
		{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -109,6 +109,7 @@
 				if(!UtilMethods.isSet(invalidCaptchaURL)) {
 					invalidCaptchaURL = errorURL;
 				}
+				invalidCaptchaURL = invalidCaptchaURL.replaceAll("\\s", " ");
 				ActionForward af = new ActionForward();
 					af.setRedirect(true);
 					if (UtilMethods.isSet(queryString)) {
```
