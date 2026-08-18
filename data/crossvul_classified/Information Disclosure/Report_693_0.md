# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 693_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `693_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 150-190 of the vulnerable file.

              D (debug_file, "Skipping comment line: %s", buf);
          continue;
      }
      if(verbose)
	  D (debug_file, "Authorization line: %s", buf);
      s_user = strtok_r (buf, ":", &saveptr);
      if (s_user && strcmp (username, s_user) == 0)
	{
	  if(verbose)
	      D (debug_file, "Matched user: %s", s_user);
      retval = AUTH_NOT_FOUND; /* We found at least one line for the user */
	  do
	    {
	      s_token = strtok_r (NULL, ":", &saveptr);
	      if(verbose)
		  D (debug_file, "Authorization token: %s", s_token);
	      if (s_token && otp_id && strcmp (otp_id, s_token) == 0)
		{
		  if(verbose)
		      D (debug_file, "Match user/token as %s/%s", username, otp_id);
		  return AUTH_FOUND;
		}
	    }
	  while (s_token != NULL);
	}
    }

  fclose (opwfile);

  return retval;
}

#if HAVE_CR
/* Fill buf with len bytes of random data */
int generate_random(void *buf, int len)
{
	FILE *u;
	int res;

	u = fopen("/dev/urandom", "r");
	if (!u) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -167,6 +167,8 @@
 		{
 		  if(verbose)
 		      D (debug_file, "Match user/token as %s/%s", username, otp_id);
+
+		  fclose(opwfile);
 		  return AUTH_FOUND;
 		}
 	    }
```
