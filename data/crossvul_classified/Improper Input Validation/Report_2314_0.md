# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2314_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2314_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 114-154 of the vulnerable file.

		rlen += rc;
	}

	return 0;
}

int net_get(int s, void *arg, int *len)
{
	struct net_hdr nh;
	int plen;

	if (net_read_exact(s, &nh, sizeof(nh)) == -1)
        {
		return -1;
        }

	plen = ntohl(nh.nh_len);
	if (!(plen <= *len))
		printf("PLEN %d type %d len %d\n",
			plen, nh.nh_type, *len);
	assert(plen <= *len); /* XXX */

	*len = plen;
	if ((*len) && (net_read_exact(s, arg, *len) == -1))
        {
            return -1;
        }

	return nh.nh_type;
}

static void queue_del(struct queue *q)
{
	q->q_prev->q_next = q->q_next;
	q->q_next->q_prev = q->q_prev;
}

static void queue_add(struct queue *head, struct queue *q)
{
	struct queue *pos = head->q_prev;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -131,7 +131,7 @@
 	if (!(plen <= *len))
 		printf("PLEN %d type %d len %d\n",
 			plen, nh.nh_type, *len);
-	assert(plen <= *len); /* XXX */
+	assert(plen <= *len && plen > 0); /* XXX */
 
 	*len = plen;
 	if ((*len) && (net_read_exact(s, arg, *len) == -1))
```
