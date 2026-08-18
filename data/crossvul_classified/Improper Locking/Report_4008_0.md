# CrossVul Fix Pair: Improper Locking in c
**Pair ID:** 4008_0
**Vulnerability Class:** Improper Locking
**CWE:** CWE-667
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4008_0`)

## Vulnerability Information & PoC

## Description
Improper Locking - Locking is a type of synchronization behavior that ensures that multiple independently-operating processes or threads do not interfere with each other when accessing the same resource.

## Vulnerable Code
```c
Lines 352-392 of the vulnerable file.

/** WORKER THREADS **/

static void *gp_worker_main(void *pvt)
{
    struct gp_thread *t = (struct gp_thread *)pvt;
    struct gp_query *q = NULL;
    char dummy = 0;
    int ret;

    while (!t->pool->shutdown) {

        /* initialize debug client id to 0 until work is scheduled */
        gp_debug_set_conn_id(0);

        /* ======> COND_MUTEX */
        pthread_mutex_lock(&t->cond_mutex);
        while (t->query == NULL) {
            /* wait for next query */
            pthread_cond_wait(&t->cond_wakeup, &t->cond_mutex);
            if (t->pool->shutdown) {
                pthread_exit(NULL);
            }
        }

        /* grab the query off the shared pointer */
        q = t->query;
        t->query = NULL;

        /* <====== COND_MUTEX */
        pthread_mutex_unlock(&t->cond_mutex);

        /* set client id before hndling requests */
        gp_debug_set_conn_id(gp_conn_get_cid(q->conn));

        /* handle the client request */
        GPDEBUGN(3, "[status] Handling query input: %p (%zu)\n", q->buffer,
                 q->buflen);
        gp_handle_query(t->pool, q);
        GPDEBUGN(3 ,"[status] Handling query output: %p (%zu)\n", q->buffer,
                 q->buflen);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -369,6 +369,7 @@
             /* wait for next query */
             pthread_cond_wait(&t->cond_wakeup, &t->cond_mutex);
             if (t->pool->shutdown) {
+                pthread_mutex_unlock(&t->cond_mutex);
                 pthread_exit(NULL);
             }
         }
```
