# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1447_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1447_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 195-235 of the vulnerable file.

    s->packet_length = rdata->packet_length;
    memcpy(&(s->s3->rbuf), &(rdata->rbuf), sizeof(SSL3_BUFFER));
    memcpy(&(s->s3->rrec), &(rdata->rrec), sizeof(SSL3_RECORD));
	
	/* Set proper sequence number for mac calculation */
	memcpy(&(s->s3->read_sequence[2]), &(rdata->packet[5]), 6);
    
    return(1);
    }


static int
dtls1_buffer_record(SSL *s, record_pqueue *queue, unsigned char *priority)
	{
	DTLS1_RECORD_DATA *rdata;
	pitem *item;

	/* Limit the size of the queue to prevent DOS attacks */
	if (pqueue_size(queue->q) >= 100)
		return 0;
		
	rdata = OPENSSL_malloc(sizeof(DTLS1_RECORD_DATA));
	item = pitem_new(priority, rdata);
	if (rdata == NULL || item == NULL)
		{
		if (rdata != NULL) OPENSSL_free(rdata);
		if (item != NULL) pitem_free(item);
		
		SSLerr(SSL_F_DTLS1_BUFFER_RECORD, ERR_R_INTERNAL_ERROR);
		return(0);
		}
	
	rdata->packet = s->packet;
	rdata->packet_length = s->packet_length;
	memcpy(&(rdata->rbuf), &(s->s3->rbuf), sizeof(SSL3_BUFFER));
	memcpy(&(rdata->rrec), &(s->s3->rrec), sizeof(SSL3_RECORD));

	item->data = rdata;

#ifndef OPENSSL_NO_SCTP
	/* Store bio_dgram_sctp_rcvinfo struct */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -212,7 +212,7 @@
 	/* Limit the size of the queue to prevent DOS attacks */
 	if (pqueue_size(queue->q) >= 100)
 		return 0;
-		
+
 	rdata = OPENSSL_malloc(sizeof(DTLS1_RECORD_DATA));
 	item = pitem_new(priority, rdata);
 	if (rdata == NULL || item == NULL)
@@ -247,18 +247,22 @@
 	if (!ssl3_setup_buffers(s))
 		{
 		SSLerr(SSL_F_DTLS1_BUFFER_RECORD, ERR_R_INTERNAL_ERROR);
+		if (rdata->rbuf.buf != NULL)
+			OPENSSL_free(rdata->rbuf.buf);
 		OPENSSL_free(rdata);
 		pitem_free(item);
-		return(0);
+		return(-1);
 		}
 
 	/* insert should not fail, since duplicates are dropped */
 	if (pqueue_insert(queue->q, item) == NULL)
 		{
 		SSLerr(SSL_F_DTLS1_BUFFER_RECORD, ERR_R_INTERNAL_ERROR);
+		if (rdata->rbuf.buf != NULL)
+			OPENSSL_free(rdata->rbuf.buf);
 		OPENSSL_free(rdata);
 		pitem_free(item);
-		return(0);
+		return(-1);
 		}
 
 	return(1);
@@ -314,8 +318,9 @@
             dtls1_get_unprocessed_record(s);
             if ( ! dtls1_process_record(s))
                 return(0);
-            dtls1_buffer_record(s, &(s->d1->processed_rcds), 
-                s->s3->rrec.seq_num);
+            if(dtls1_buffer_record(s, &(s->d1->processed_rcds),
+                s->s3->rrec.seq_num)<0)
+                return -1;
             }
         }
 
@@ -529,7 +534,6 @@
 
 	/* we have pulled in a full packet so zero things */
 	s->packet_length=0;
-	dtls1_record_bitmap_update(s, &(s->d1->bitmap));/* Mark receipt of record. */
 	return(1);
 
 f_err:
@@ -563,7 +567,8 @@
 
 	/* The epoch may have changed.  If so, process all the
 	 * pending records.  This is a non-blocking operation. */
-	dtls1_process_buffered_records(s);
+	if(dtls1_process_buffered_records(s)<0)
+		return -1;
 
 	/* if we're renegotiating, then there may be buffered records */
 	if (dtls1_get_processed_record(s))
@@ -703,7 +708,9 @@
 		{
 		if ((SSL_in_init(s) || s->in_handshake) && !s->d1->listen)
 			{
-			dtls1_buffer_record(s, &(s->d1->unprocessed_rcds), rr->seq_num);
+			if(dtls1_buffer_record(s, &(s->d1->unprocessed_rcds), rr->seq_num)<0)
+				return -1;
+			dtls1_record_bitmap_update(s, bitmap);/* Mark receipt of record. */
 			}
 		rr->length = 0;
 		s->packet_length = 0;
@@ -716,6 +723,7 @@
 		s->packet_length = 0;  /* dump this record */
 		goto again;   /* get another record */
 		}
+	dtls1_record_bitmap_update(s, bitmap);/* Mark receipt of record. */
 
 	return(1);
 
@@ -869,7 +877,11 @@
 		 * buffer the application data for later processing rather
 		 * than dropping the connection.
 		 */
-		dtls1_buffer_record(s, &(s->d1->buffered_app_data), rr->seq_num);
+		if(dtls1_buffer_record(s, &(s->d1->buffered_app_data), rr->seq_num)<0)
+			{
+			SSLerr(SSL_F_DTLS1_READ_BYTES, ERR_R_INTERNAL_ERROR);
+			return -1;
+			}
 		rr->length = 0;
 		goto start;
 		}
```
