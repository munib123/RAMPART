# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in java
**Pair ID:** 5029_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5029_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```java
Lines 401-441 of the vulnerable file.

				WebForm formBean = saveFormBean(parameters, host, formType, ignoreString, filesLinks);


				// Setting up the email
				// Email variables - decrypting crypted email addresses 

				String from = UtilMethods.replace((String)getMapValue("from", parameters), "spamx", "");
				String to = UtilMethods.replace((String)getMapValue("to", parameters), "spamx", "");
				String cc = UtilMethods.replace((String)getMapValue("cc", parameters), "spamx", "");
				String bcc = UtilMethods.replace((String)getMapValue("bcc", parameters), "spamx", "");
				String fromName = UtilMethods.replace((String)getMapValue("fromName", parameters), "spamx", "");
				try { from = PublicEncryptionFactory.decryptString(from); } catch (Exception e) { }
				try { to = PublicEncryptionFactory.decryptString(to); } catch (Exception e) { }
				try { cc = PublicEncryptionFactory.decryptString(cc); } catch (Exception e) { }
				try { bcc = PublicEncryptionFactory.decryptString(bcc); } catch (Exception e) { }
				try { fromName = PublicEncryptionFactory.decryptString(fromName); } catch (Exception e) { }

				String subject = (String)getMapValue("subject", parameters);
				subject = (subject == null) ? "Mail from " + host.getHostname() + "" : subject;

				String emailFolder = (String)getMapValue("emailFolder", parameters);

				boolean html = getMapValue("html", parameters) != null?Parameter.getBooleanFromString((String)getMapValue("html", parameters)):true;

				String templatePath = (String) getMapValue("emailTemplate", parameters);

				// Building email message no template
				Map<String, String> emailBodies = null;

				try {
					emailBodies = buildEmail(templatePath, host, orderedMap, prettyVariableNamesMap, filesLinks.toString(), ignoreString, user);
				} catch (Exception e) {
					Logger.error(EmailFactory.class, "sendForm: Couldn't build the email body text.", e);
					throw new DotRuntimeException("sendForm: Couldn't build the email body text.", e);
				}

				// Saving email backup in a file
				try {
					String filePath = FileUtil.getRealPath(Config.getStringProperty("EMAIL_BACKUPS"));
					new File(filePath).mkdir();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -418,6 +418,23 @@
 				String subject = (String)getMapValue("subject", parameters);
 				subject = (subject == null) ? "Mail from " + host.getHostname() + "" : subject;
 
+				
+				// strip line breaks from headers
+				from = from.replaceAll("\\s", " ");
+				to = to.replaceAll("\\s", " ");
+				cc = cc.replaceAll("\\s", " ");
+				bcc = bcc.replaceAll("\\s", " ");
+				fromName = fromName.replaceAll("\\s", " ");
+				subject = subject.replaceAll("\\s", " ");
+				
+				
+				
+				
+				
+				
+				
+				
+				
 				String emailFolder = (String)getMapValue("emailFolder", parameters);
 
 				boolean html = getMapValue("html", parameters) != null?Parameter.getBooleanFromString((String)getMapValue("html", parameters)):true;
```
