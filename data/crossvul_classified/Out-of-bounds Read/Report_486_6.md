# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 486_6
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `486_6`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 28-68 of the vulnerable file.


/* Output a DOMAIN_PARAMS structure (ASN.1 BER) */
static void
mcs_out_domain_params(STREAM s, int max_channels, int max_users, int max_tokens, int max_pdusize)
{
	ber_out_header(s, MCS_TAG_DOMAIN_PARAMS, 32);
	ber_out_integer(s, max_channels);
	ber_out_integer(s, max_users);
	ber_out_integer(s, max_tokens);
	ber_out_integer(s, 1);	/* num_priorities */
	ber_out_integer(s, 0);	/* min_throughput */
	ber_out_integer(s, 1);	/* max_height */
	ber_out_integer(s, max_pdusize);
	ber_out_integer(s, 2);	/* ver_protocol */
}

/* Parse a DOMAIN_PARAMS structure (ASN.1 BER) */
static RD_BOOL
mcs_parse_domain_params(STREAM s)
{
	int length;

	ber_parse_header(s, MCS_TAG_DOMAIN_PARAMS, &length);
	in_uint8s(s, length);

	return s_check(s);
}

/* Send an MCS_CONNECT_INITIAL message (ASN.1 BER) */
static void
mcs_send_connect_initial(STREAM mcs_data)
{
	int datalen = mcs_data->end - mcs_data->data;
	int length = 9 + 3 * 34 + 4 + datalen;
	STREAM s;
	logger(Protocol, Debug, "%s()", __func__);
	s = iso_init(length + 5);

	ber_out_header(s, MCS_CONNECT_INITIAL, length);
	ber_out_header(s, BER_TAG_OCTET_STRING, 1);	/* calling domain */
	out_uint8(s, 1);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,9 +45,16 @@
 static RD_BOOL
 mcs_parse_domain_params(STREAM s)
 {
-	int length;
+	uint32 length;
+	struct stream packet = *s;
 
 	ber_parse_header(s, MCS_TAG_DOMAIN_PARAMS, &length);
+
+	if (!s_check_rem(s, length))
+	{
+		rdp_protocol_error("mcs_parse_domain_params(), consume domain params from stream would overrun", &packet);
+	}
+
 	in_uint8s(s, length);
 
 	return s_check(s);
@@ -89,8 +96,9 @@
 {
 	UNUSED(mcs_data);
 	uint8 result;
-	int length;
-	STREAM s;
+	uint32 length;
+	STREAM s;
+	struct stream packet;
 	RD_BOOL is_fastpath;
 	uint8 fastpath_hdr;
 
@@ -99,6 +107,8 @@
 
 	if (s == NULL)
 		return False;
+	
+	packet = *s;
 
 	ber_parse_header(s, MCS_CONNECT_RESPONSE, &length);
 
@@ -112,6 +122,12 @@
 
 	ber_parse_header(s, BER_TAG_INTEGER, &length);
 	in_uint8s(s, length);	/* connect id */
+
+	if (!s_check_rem(s, length))
+	{
+		rdp_protocol_error("mcs_recv_connect_response(), consume connect id from stream would overrun", &packet);
+	}
+
 	mcs_parse_domain_params(s);
 
 	ber_parse_header(s, BER_TAG_OCTET_STRING, &length);
```
