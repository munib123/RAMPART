# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4214_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4214_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 4790-4830 of the vulnerable file.

	val *= 16;
	val += *str + 10 - 'A';
      } else {
	break;
      }
      str++;
      max_chars_to_read = max_chars_to_read - 1;
      *bytes_read = *bytes_read + 1;
    }
  }
  return(val);
}

/* ********************************************************************************* */

u_int32_t ndpi_bytestream_to_ipv4(const u_int8_t *str, u_int16_t max_chars_to_read, u_int16_t *bytes_read) {
  u_int32_t val;
  u_int16_t read = 0;
  u_int16_t oldread;
  u_int32_t c;
  /* ip address must be X.X.X.X with each X between 0 and 255 */
  oldread = read;
  c = ndpi_bytestream_to_number(str, max_chars_to_read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
    return(0);
  read++;
  val = c << 24;
  oldread = read;
  c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
    return(0);
  read++;
  val = val + (c << 16);
  oldread = read;
  c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
    return(0);
  read++;
  val = val + (c << 8);
  oldread = read;
  c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4807,29 +4807,34 @@
   u_int16_t read = 0;
   u_int16_t oldread;
   u_int32_t c;
+
   /* ip address must be X.X.X.X with each X between 0 and 255 */
   oldread = read;
   c = ndpi_bytestream_to_number(str, max_chars_to_read, &read);
   if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
     return(0);
+  
   read++;
   val = c << 24;
   oldread = read;
   c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
   if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
     return(0);
+  
   read++;
   val = val + (c << 16);
   oldread = read;
   c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
   if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
     return(0);
+  
   read++;
   val = val + (c << 8);
   oldread = read;
   c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
   if(c > 255 || oldread == read || max_chars_to_read == read)
     return(0);
+  
   val = val + c;
 
   *bytes_read = *bytes_read + read;
@@ -4869,9 +4874,10 @@
 	int diff; /* No unsigned ! */
 	u_int32_t a1 = a + 4;
 
-	diff = ndpi_min(packet->payload_packet_len-a1, sizeof(flow->initial_binary_bytes));
+	diff = packet->payload_packet_len - a1;
 
 	if(diff > 0) {
+	  diff = ndpi_min(diff, sizeof(flow->initial_binary_bytes));
 	  memcpy(&flow->initial_binary_bytes, &packet->payload[a1], diff);
 	  flow->initial_binary_bytes_len = diff;
 	}
```
