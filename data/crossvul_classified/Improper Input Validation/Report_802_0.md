# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 802_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `802_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 38-81 of the vulnerable file.

        myHostname = sydent.cfg.get('email', 'email.hostname')
        if myHostname == '':
            myHostname = socket.getfqdn()
        midRandom = "".join([random.choice(string.ascii_letters) for _ in range(16)])
        messageid = "<%d%s@%s>" % (time_msec(), midRandom, myHostname)

        allSubstitutions = {}
        allSubstitutions.update(substitutions)
        allSubstitutions.update({
            'messageid': messageid,
            'date': email.utils.formatdate(localtime=False),
            'to': mailTo,
            'from': mailFrom,
        })

        for k,v in allSubstitutions.items():
            allSubstitutions[k] = v.decode('utf8')
            allSubstitutions[k+"_forhtml"] = cgi.escape(v.decode('utf8'))
            allSubstitutions[k+"_forurl"] = urllib.quote(v)

        mailString = open(mailTemplateFile).read() % allSubstitutions
        rawFrom = email.utils.parseaddr(mailFrom)[1]
        rawTo = email.utils.parseaddr(mailTo)[1]
        if rawFrom == '' or rawTo == '':
            logger.info("Couldn't parse from / to address %s / %s", mailFrom, mailTo)
            raise EmailAddressException()
        mailServer = sydent.cfg.get('email', 'email.smtphost')
        mailPort = sydent.cfg.get('email', 'email.smtpport')
        mailUsername = sydent.cfg.get('email', 'email.smtpusername')
        mailPassword = sydent.cfg.get('email', 'email.smtppassword')
        mailTLSMode = sydent.cfg.get('email', 'email.tlsmode')
        logger.info("Sending mail to %s with mail server: %s" % (mailTo, mailServer,))
        try:
            if mailTLSMode == 'SSL' or mailTLSMode == 'TLS':
                smtp = smtplib.SMTP_SSL(mailServer, mailPort, myHostname)
            elif mailTLSMode == 'STARTTLS':
                smtp = smtplib.SMTP(mailServer, mailPort, myHostname)
                smtp.starttls()
            else:
                smtp = smtplib.SMTP(mailServer, mailPort, myHostname)
            if mailUsername != '':
                smtp.login(mailUsername, mailPassword)
            smtp.sendmail(rawFrom, rawTo, mailString.encode('utf-8'))
            smtp.quit()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,12 +55,13 @@
             allSubstitutions[k+"_forhtml"] = cgi.escape(v.decode('utf8'))
             allSubstitutions[k+"_forurl"] = urllib.quote(v)
 
-        mailString = open(mailTemplateFile).read() % allSubstitutions
-        rawFrom = email.utils.parseaddr(mailFrom)[1]
-        rawTo = email.utils.parseaddr(mailTo)[1]
-        if rawFrom == '' or rawTo == '':
+        mailString = open(mailTemplateFile).read().decode('utf8') % allSubstitutions
+        parsedFrom = email.utils.parseaddr(mailFrom)[1]
+        parsedTo = email.utils.parseaddr(mailTo)[1]
+        if parsedFrom == '' or parsedTo == '':
             logger.info("Couldn't parse from / to address %s / %s", mailFrom, mailTo)
             raise EmailAddressException()
+
         mailServer = sydent.cfg.get('email', 'email.smtphost')
         mailPort = sydent.cfg.get('email', 'email.smtpport')
         mailUsername = sydent.cfg.get('email', 'email.smtpusername')
@@ -77,7 +78,12 @@
                 smtp = smtplib.SMTP(mailServer, mailPort, myHostname)
             if mailUsername != '':
                 smtp.login(mailUsername, mailPassword)
-            smtp.sendmail(rawFrom, rawTo, mailString.encode('utf-8'))
+
+            # We're using the parsing above to do basic validation, but instead of
+            # failing it may munge the address it returns. So we should *not* use
+            # that parsed address, as it may not match any validation done
+            # elsewhere.
+            smtp.sendmail(mailFrom, mailTo, mailString.encode('utf-8'))
             smtp.quit()
         except Exception as origException:
             twisted.python.log.err()
```
