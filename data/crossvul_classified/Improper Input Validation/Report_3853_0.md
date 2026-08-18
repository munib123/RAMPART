# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 3853_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3853_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 743-783 of the vulnerable file.

	while ((unsigned)curanswer < header.ancount)
	{
		q = 0;
		while (q == 0 && i < length)
		{
			if (header.payload[i] > 63)
			{
				i += 2;
				q = 1;
			}
			else
			{
				if (header.payload[i] == 0)
				{
					i++;
					q = 1;
				}
				else i += header.payload[i] + 1; /* skip length and label */
			}
		}
		if (length - i < 10)
			return std::make_pair((unsigned char*)NULL,"Incorrectly sized DNS reply");

		/* XXX: We actually initialise 'rr' here including its ttl field */
		DNS::FillResourceRecord(&rr,&header.payload[i]);

		i += 10;
		ServerInstance->Logs->Log("RESOLVER",DEBUG,"Resolver: rr.type is %d and this.type is %d rr.class %d this.class %d", rr.type, this->type, rr.rr_class, this->rr_class);
		if (rr.type != this->type)
		{
			curanswer++;
			i += rr.rdlength;
			continue;
		}
		if (rr.rr_class != this->rr_class)
		{
			curanswer++;
			i += rr.rdlength;
			continue;
		}
		break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -760,7 +760,7 @@
 				else i += header.payload[i] + 1; /* skip length and label */
 			}
 		}
-		if (length - i < 10)
+		if (static_cast<int>(length - i) < 10)
 			return std::make_pair((unsigned char*)NULL,"Incorrectly sized DNS reply");
 
 		/* XXX: We actually initialise 'rr' here including its ttl field */
```
