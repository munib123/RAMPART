# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 5268_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5268_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 133-173 of the vulnerable file.


  /* If it's to us, do nothing; otherwise, forward the query */
  if (acptr && IsMe(acptr))
    return 0;

  /* Generate an SASL session cookie if not already generated */
  if (!cli_saslcookie(cptr)) {
    do {
      cli_saslcookie(cptr) = ircrandom() & 0x7fffffff;
    } while (!cli_saslcookie(cptr));
    first = 1;
  }

  if (strchr(hoststr, ':') != NULL)
    ircd_snprintf(0, realhost, sizeof(realhost), "[%s]", hoststr);
  else
    ircd_strncpy(realhost, hoststr, sizeof(realhost));

  if (acptr) {
    if (first) {
      if (!EmptyString(cli_sslclifp(cptr)))
        sendcmdto_one(&me, CMD_SASL, acptr, "%C %C!%u.%u S %s :%s", acptr, &me,
                      cli_fd(cptr), cli_saslcookie(cptr),
                      parv[1], cli_sslclifp(cptr));
      else
        sendcmdto_one(&me, CMD_SASL, acptr, "%C %C!%u.%u S :%s", acptr, &me,
                      cli_fd(cptr), cli_saslcookie(cptr), parv[1]);
      if (feature_bool(FEAT_SASL_SENDHOST))
        sendcmdto_one(&me, CMD_SASL, acptr, "%C %C!%u.%u H :%s@%s:%s", acptr, &me,
                      cli_fd(cptr), cli_saslcookie(cptr), cli_username(cptr),
                      realhost, cli_sock_ip(cptr));
    } else {
      sendcmdto_one(&me, CMD_SASL, acptr, "%C %C!%u.%u C :%s", acptr, &me,
                    cli_fd(cptr), cli_saslcookie(cptr), parv[1]);
    }
  } else {
    if (first) {
      if (!EmptyString(cli_sslclifp(cptr)))
        sendcmdto_serv_butone(&me, CMD_SASL, cptr, "* %C!%u.%u S %s :%s", &me,
                              cli_fd(cptr), cli_saslcookie(cptr),
                              parv[1], cli_sslclifp(cptr));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -150,6 +150,8 @@
 
   if (acptr) {
     if (first) {
+      if (*parv[1] == ':' || strchr(parv[1], ' '))
+		return exit_client(cptr, sptr, sptr, "Malformed AUTHENTICATE");
       if (!EmptyString(cli_sslclifp(cptr)))
         sendcmdto_one(&me, CMD_SASL, acptr, "%C %C!%u.%u S %s :%s", acptr, &me,
                       cli_fd(cptr), cli_saslcookie(cptr),
@@ -167,6 +169,8 @@
     }
   } else {
     if (first) {
+      if (*parv[1] == ':' || strchr(parv[1], ' '))
+        return exit_client(cptr, sptr, sptr, "Malformed AUTHENTICATE");
       if (!EmptyString(cli_sslclifp(cptr)))
         sendcmdto_serv_butone(&me, CMD_SASL, cptr, "* %C!%u.%u S %s :%s", &me,
                               cli_fd(cptr), cli_saslcookie(cptr),
```
