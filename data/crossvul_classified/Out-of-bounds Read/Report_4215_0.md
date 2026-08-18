# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4215_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4215_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1187-1227 of the vulnerable file.

	      ndpi_data_min(flow->iat_c_to_s),     ndpi_data_min(flow->iat_s_to_c),
	      (float)ndpi_data_average(flow->iat_c_to_s), (float)ndpi_data_average(flow->iat_s_to_c),
	      ndpi_data_max(flow->iat_c_to_s),     ndpi_data_max(flow->iat_s_to_c),
	      (float)ndpi_data_stddev(flow->iat_c_to_s),  (float)ndpi_data_stddev(flow->iat_s_to_c));

      /* Packet Length */
      fprintf(out, "[Pkt Len c2s/s2c min/avg/max/stddev: %u/%u %.0f/%.0f %u/%u %.0f/%.0f]",
	      ndpi_data_min(flow->pktlen_c_to_s), ndpi_data_min(flow->pktlen_s_to_c),
	      ndpi_data_average(flow->pktlen_c_to_s), ndpi_data_average(flow->pktlen_s_to_c),
	      ndpi_data_max(flow->pktlen_c_to_s), ndpi_data_max(flow->pktlen_s_to_c),
	      ndpi_data_stddev(flow->pktlen_c_to_s),  ndpi_data_stddev(flow->pktlen_s_to_c));
    }
  }

  if(flow->http.url[0] != '\0') {
    ndpi_risk_enum risk = ndpi_validate_url(flow->http.url);

    if(risk != NDPI_NO_RISK)
      NDPI_SET_BIT(flow->risk, risk);
    
    fprintf(out, "[URL: %s[StatusCode: %u]",
	    flow->http.url, flow->http.response_status_code);

    if(flow->http.content_type[0] != '\0')
      fprintf(out, "[ContentType: %s]", flow->http.content_type);

    if(flow->http.user_agent[0] != '\0')
      fprintf(out, "[UserAgent: %s]", flow->http.user_agent);
  }

  if(flow->risk) {
    u_int i;
    
    fprintf(out, "[Risk: ");

    for(i=0; i<NDPI_MAX_RISK; i++)
      if(NDPI_ISSET_BIT(flow->risk, i))
	fprintf(out, "** %s **", ndpi_risk2str(i));
    
    fprintf(out, "]");
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1204,14 +1204,14 @@
     if(risk != NDPI_NO_RISK)
       NDPI_SET_BIT(flow->risk, risk);
     
-    fprintf(out, "[URL: %s[StatusCode: %u]",
+    fprintf(out, "[URL: %s][StatusCode: %u]",
 	    flow->http.url, flow->http.response_status_code);
 
     if(flow->http.content_type[0] != '\0')
-      fprintf(out, "[ContentType: %s]", flow->http.content_type);
+      fprintf(out, "[Content-Type: %s]", flow->http.content_type);
 
     if(flow->http.user_agent[0] != '\0')
-      fprintf(out, "[UserAgent: %s]", flow->http.user_agent);
+      fprintf(out, "[User-Agent: %s]", flow->http.user_agent);
   }
 
   if(flow->risk) {
```
