# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2308_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2308_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 185-227 of the vulnerable file.

        }

    while( (item = pqueue_pop(s->d1->buffered_messages)) != NULL)
        {
        frag = (hm_fragment *)item->data;
        OPENSSL_free(frag->fragment);
        OPENSSL_free(frag);
        pitem_free(item);
        }

    while ( (item = pqueue_pop(s->d1->sent_messages)) != NULL)
        {
        frag = (hm_fragment *)item->data;
        OPENSSL_free(frag->fragment);
        OPENSSL_free(frag);
        pitem_free(item);
        }

	while ( (item = pqueue_pop(s->d1->buffered_app_data.q)) != NULL)
		{
		frag = (hm_fragment *)item->data;
		OPENSSL_free(frag->fragment);
		OPENSSL_free(frag);
		pitem_free(item);
		}
	}

void dtls1_free(SSL *s)
	{
	ssl3_free(s);

	dtls1_clear_queues(s);

    pqueue_free(s->d1->unprocessed_rcds.q);
    pqueue_free(s->d1->processed_rcds.q);
    pqueue_free(s->d1->buffered_messages);
	pqueue_free(s->d1->sent_messages);
	pqueue_free(s->d1->buffered_app_data.q);

	OPENSSL_free(s->d1);
	s->d1 = NULL;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -202,9 +202,12 @@
 
 	while ( (item = pqueue_pop(s->d1->buffered_app_data.q)) != NULL)
 		{
-		frag = (hm_fragment *)item->data;
-		OPENSSL_free(frag->fragment);
-		OPENSSL_free(frag);
+		rdata = (DTLS1_RECORD_DATA *) item->data;
+		if (rdata->rbuf.buf)
+			{
+			OPENSSL_free(rdata->rbuf.buf);
+			}
+		OPENSSL_free(item->data);
 		pitem_free(item);
 		}
 	}
```
