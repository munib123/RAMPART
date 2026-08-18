# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 486_4
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `486_4`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 578-618 of the vulnerable file.

	out_uint8p(s, h1->data, s_length(h1));
	s_mark_end(s);
	s_free(h1);

	tcp_send(s);

	// cleanup
	xfree(message.data);
	xfree(tmp.data);

	return True;
}


RD_BOOL
cssp_read_tsrequest(STREAM token, STREAM pubkey)
{
	STREAM s;
	int length;
	int tagval;

	s = tcp_recv(NULL, 4);

	if (s == NULL)
		return False;

	// verify ASN.1 header
	if (s->p[0] != (BER_TAG_SEQUENCE | BER_TAG_CONSTRUCTED))
	{
		logger(Protocol, Error,
		       "cssp_read_tsrequest(), expected BER_TAG_SEQUENCE|BER_TAG_CONSTRUCTED, got %x",
		       s->p[0]);
		return False;
	}

	// peek at first 4 bytes to get full message length
	if (s->p[1] < 0x80)
		length = s->p[1] - 2;
	else if (s->p[1] == 0x81)
		length = s->p[2] - 1;
	else if (s->p[1] == 0x82)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -595,6 +595,7 @@
 	STREAM s;
 	int length;
 	int tagval;
+	struct stream packet;
 
 	s = tcp_recv(NULL, 4);
 
@@ -622,6 +623,7 @@
 
 	// receive the remainings of message
 	s = tcp_recv(s, length);
+	packet = *s;
 
 	// parse the response and into nego token
 	if (!ber_in_header(s, &tagval, &length) ||
@@ -632,6 +634,12 @@
 	if (!ber_in_header(s, &tagval, &length) ||
 	    tagval != (BER_TAG_CTXT_SPECIFIC | BER_TAG_CONSTRUCTED | 0))
 		return False;
+
+	if (!s_check_rem(s, length))
+	{
+		 rdp_protocol_error("cssp_read_tsrequest(), consume of version from stream would overrun",
+				    &packet);
+	}
 	in_uint8s(s, length);
 
 	// negoToken [1]
@@ -653,7 +661,14 @@
 		if (!ber_in_header(s, &tagval, &length) || tagval != BER_TAG_OCTET_STRING)
 			return False;
 
-		token->end = token->p = token->data;
+		if (!s_check_rem(s, length))
+		{
+			rdp_protocol_error("cssp_read_tsrequest(), consume of token from stream would overrun",
+					   &packet);
+		}
+
+		s_realloc(token, length);
+		s_reset(token);
 		out_uint8p(token, s->p, length);
 		s_mark_end(token);
 	}
```
