# CrossVul Fix Pair: 7PK in c
**Pair ID:** 5008_0
**Vulnerability Class:** 7PK
**CWE:** CWE-388
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5008_0`)

## Vulnerability Information & PoC

## Description
7PK - Errors

## Vulnerable Code
```c
Lines 641-681 of the vulnerable file.

				CODELENGTH(m, rp);
				memcpy(rp, serv->usn, m);
				rp += m;
				nrep++;
			}
		}
		rbuf[0] = nrep;
		syslog(LOG_DEBUG, "(s=%d) response : %d device%s",
		       req->socket, nrep, (nrep > 1) ? "s" : "");
		if(write(req->socket, rbuf, rp - rbuf) < 0) {
			syslog(LOG_ERR, "(s=%d) write: %m", req->socket);
			goto error;
		}
		break;
	case 4:	/* submit service */
		newserv = malloc(sizeof(struct service));
		if(!newserv) {
			syslog(LOG_ERR, "cannot allocate memory");
			goto error;
		}
		if(containsForbiddenChars(p, l)) {
			syslog(LOG_ERR, "bad request (st contains forbidden chars)");
			goto error;
		}
		newserv->st = malloc(l + 1);
		if(!newserv->st) {
			syslog(LOG_ERR, "cannot allocate memory");
			goto error;
		}
		memcpy(newserv->st, p, l);
		newserv->st[l] = '\0';
		p += l;
		if(p >= buf + n) {
			syslog(LOG_WARNING, "bad request (missing usn)");
			goto error;
		}
		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
		if(p+l > buf+n) {
			syslog(LOG_WARNING, "bad request (length encoding)");
			goto error;
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -658,6 +658,7 @@
 			syslog(LOG_ERR, "cannot allocate memory");
 			goto error;
 		}
+		memset(newserv, 0, sizeof(struct service));	/* set pointers to NULL */
 		if(containsForbiddenChars(p, l)) {
 			syslog(LOG_ERR, "bad request (st contains forbidden chars)");
 			goto error;
```
