# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 860_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `860_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 426-470 of the vulnerable file.

#ifdef ENABLE_L3F_SERVICE
	case EL3F:
		xml = getVarsL3F(&l);
		break;
#endif
#ifdef ENABLE_6FC_SERVICE
	case E6FC:
		xml = getVars6FC(&l);
		break;
#endif
#ifdef ENABLE_DP_SERVICE
	case EDP:
		xml = getVarsDP(&l);
		break;
#endif
	default:
		xml = NULL;
		l = 0;
	}
	obj->buffersize = 1024;
	obj->buffer = malloc(obj->buffersize);
	if(!obj->buffer) {
		syslog(LOG_ERR, "%s: malloc returned NULL", "upnp_event_prepare");
		if(xml) {
			free(xml);
		}
		obj->state = EError;
		return;
	}
	obj->tosend = snprintf(obj->buffer, obj->buffersize, notifymsg,
	                       obj->path, obj->addrstr, obj->portstr, l+2,
	                       obj->sub->uuid, obj->sub->seq,
	                       l, xml);
	if(xml) {
		free(xml);
		xml = NULL;
	}
	obj->state = ESending;
}

static void upnp_event_send(struct upnp_event_notify * obj)
{
	int i;

	syslog(LOG_DEBUG, "%s: sending event notify message to %s%s",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -443,19 +443,34 @@
 		l = 0;
 	}
 	obj->buffersize = 1024;
-	obj->buffer = malloc(obj->buffersize);
-	if(!obj->buffer) {
-		syslog(LOG_ERR, "%s: malloc returned NULL", "upnp_event_prepare");
-		if(xml) {
-			free(xml);
-		}
-		obj->state = EError;
-		return;
-	}
-	obj->tosend = snprintf(obj->buffer, obj->buffersize, notifymsg,
-	                       obj->path, obj->addrstr, obj->portstr, l+2,
-	                       obj->sub->uuid, obj->sub->seq,
-	                       l, xml);
+	for (;;) {
+		obj->buffer = malloc(obj->buffersize);
+		if(!obj->buffer) {
+			syslog(LOG_ERR, "%s: malloc returned NULL", "upnp_event_prepare");
+			if(xml) {
+				free(xml);
+			}
+			obj->state = EError;
+			return;
+		}
+		obj->tosend = snprintf(obj->buffer, obj->buffersize, notifymsg,
+		                       obj->path, obj->addrstr, obj->portstr, l+2,
+		                       obj->sub->uuid, obj->sub->seq,
+		                       l, xml);
+		if (obj->tosend < 0) {
+			syslog(LOG_ERR, "%s: snprintf() failed", "upnp_event_prepare");
+			if(xml) {
+				free(xml);
+			}
+			obj->state = EError;
+			return;
+		} else if (obj->tosend < obj->buffersize) {
+			break; /* the buffer was large enough */
+		}
+		/* Try again with a buffer big enough */
+		free(obj->buffer);
+		obj->buffersize = obj->tosend + 1;	/* reserve space for the final 0 */
+	}
 	if(xml) {
 		free(xml);
 		xml = NULL;
```
