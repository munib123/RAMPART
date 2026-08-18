# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3394_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3394_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 86-126 of the vulnerable file.

  naliases = 0;

  /* Examine each answer resource record (RR) in turn. */
  for (i = 0; i < (int)ancount; i++)
    {
      /* Decode the RR up to the data field. */
      status = ares_expand_name(aptr, abuf, alen, &rr_name, &len);
      if (status != ARES_SUCCESS)
	break;
      aptr += len;
      if (aptr + RRFIXEDSZ > abuf + alen)
	{
	  free(rr_name);
	  status = ARES_EBADRESP;
	  break;
	}
      rr_type = DNS_RR_TYPE(aptr);
      rr_class = DNS_RR_CLASS(aptr);
      rr_len = DNS_RR_LEN(aptr);
      aptr += RRFIXEDSZ;

      if (rr_class == C_IN && rr_type == T_A
	  && rr_len == sizeof(struct in_addr)
	  && strcasecmp(rr_name, hostname) == 0)
	{
	  memcpy(&addrs[naddrs], aptr, sizeof(struct in_addr));
	  naddrs++;
	  status = ARES_SUCCESS;
	}

      if (rr_class == C_IN && rr_type == T_CNAME)
	{
	  /* Record the RR name as an alias. */
	  aliases[naliases] = rr_name;
	  naliases++;

	  /* Decode the RR data and replace the hostname with it. */
	  status = ares_expand_name(aptr, abuf, alen, &rr_data, &len);
	  if (status != ARES_SUCCESS)
	    break;
	  free(hostname);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,6 +103,12 @@
       rr_class = DNS_RR_CLASS(aptr);
       rr_len = DNS_RR_LEN(aptr);
       aptr += RRFIXEDSZ;
+      if (aptr + rr_len > abuf + alen)
+	{
+	  free(rr_name);
+	  status = ARES_EBADRESP;
+	  break;
+	}
 
       if (rr_class == C_IN && rr_type == T_A
 	  && rr_len == sizeof(struct in_addr)
```
