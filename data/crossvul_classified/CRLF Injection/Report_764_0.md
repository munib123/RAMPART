# CrossVul Fix Pair: Improper Neutralization of CRLF Sequences ('CRLF Injection') in cpp
**Pair ID:** 764_0
**Vulnerability Class:** CRLF Injection
**CWE:** CWE-93
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `764_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of CRLF Sequences ('CRLF Injection') - The product uses CRLF (carriage return line feeds) as a special element, e.

## Vulnerable Code
```cpp
Lines 997-1037 of the vulnerable file.

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

const char *szInsecureArgumentOptions[] = {
	"import",
	"socket",
	"process",
	"os",
	"|",
	";",
	"&",
	"$",
	"<",
	">",
	NULL
};

bool IsArgumentSecure(const std::string &arg)
{
	std::string larg(arg);
	std::transform(larg.begin(), larg.end(), larg.begin(), ::tolower);

	int ii = 0;
	while (szInsecureArgumentOptions[ii] != NULL)
	{
		if (larg.find(szInsecureArgumentOptions[ii]) != std::string::npos)
			return false;
		ii++;
	}
	return true;
}

uint32_t SystemUptime()
{
#if defined(WIN32)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1014,6 +1014,8 @@
 	"$",
 	"<",
 	">",
+	"\n",
+	"\r",
 	NULL
 };
 
```
