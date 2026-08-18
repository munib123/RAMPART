# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 1798_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1798_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 683-723 of the vulnerable file.

					delete req;
					return DNSResult(this_id | ERROR_MASK, "inet_ntop() failed", 0, ro);
				}

				resultstr = formatted;

				/* Special case. Sending ::1 around between servers
				 * and to clients is dangerous, because the : on the
				 * start makes the client or server interpret the IP
				 * as the last parameter on the line with a value ":1".
				 */
				if (*formatted == ':')
					resultstr.insert(0, "0");
			}
			break;

			case DNS_QUERY_CNAME:
				/* Identical handling to PTR */

			case DNS_QUERY_PTR:
				/* Reverse lookups just come back as char* */
				resultstr = std::string((const char*)data.first);
			break;

			default:
			break;
		}

		/* Build the reply with the id and hostname/ip in it */
		std::string ro = req->orig;
		DNSResult result = DNSResult(this_id,resultstr,ttl,ro,req->type);
		delete req;
		return result;
	}
}

/** A result is ready, process it */
DNSInfo DNSRequest::ResultIsReady(DNSHeader &header, unsigned length)
{
	unsigned i = 0, o;
	int q = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -700,8 +700,16 @@
 				/* Identical handling to PTR */
 
 			case DNS_QUERY_PTR:
+			{
 				/* Reverse lookups just come back as char* */
 				resultstr = std::string((const char*)data.first);
+				if (resultstr.find_first_not_of("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-") != std::string::npos)
+				{
+					std::string ro = req->orig;
+					delete req;
+					return DNSResult(this_id | ERROR_MASK, "Invalid char(s) in reply", 0, ro);
+				}
+			}
 			break;
 
 			default:
```
