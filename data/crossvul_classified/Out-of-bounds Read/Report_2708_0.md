# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2708_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2708_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 486-529 of the vulnerable file.


/*****************************/
/* Print an attribute string */
/* value pointed by 'data'   */
/* and 'length' size.        */
/*****************************/
/* Returns nothing.          */
/*****************************/
static void
print_attr_string(netdissect_options *ndo,
                  register const u_char *data, u_int length, u_short attr_code)
{
   register u_int i;

   ND_TCHECK2(data[0],length);

   switch(attr_code)
   {
      case TUNNEL_PASS:
           if (length < 3)
           {
              ND_PRINT((ndo, "%s", tstr));
              return;
           }
           if (*data && (*data <=0x1F) )
              ND_PRINT((ndo, "Tag[%u] ", *data));
           else
              ND_PRINT((ndo, "Tag[Unused] "));
           data++;
           length--;
           ND_PRINT((ndo, "Salt %u ", EXTRACT_16BITS(data)));
           data+=2;
           length-=2;
        break;
      case TUNNEL_CLIENT_END:
      case TUNNEL_SERVER_END:
      case TUNNEL_PRIV_GROUP:
      case TUNNEL_ASSIGN_ID:
      case TUNNEL_CLIENT_AUTH:
      case TUNNEL_SERVER_AUTH:
           if (*data <= 0x1F)
           {
              if (length < 1)
              {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -503,10 +503,7 @@
    {
       case TUNNEL_PASS:
            if (length < 3)
-           {
-              ND_PRINT((ndo, "%s", tstr));
-              return;
-           }
+              goto trunc;
            if (*data && (*data <=0x1F) )
               ND_PRINT((ndo, "Tag[%u] ", *data));
            else
@@ -526,10 +523,7 @@
            if (*data <= 0x1F)
            {
               if (length < 1)
-              {
-                 ND_PRINT((ndo, "%s", tstr));
-                 return;
-              }
+                 goto trunc;
               if (*data)
                 ND_PRINT((ndo, "Tag[%u] ", *data));
               else
@@ -539,6 +533,8 @@
            }
         break;
       case EGRESS_VLAN_NAME:
+           if (length < 1)
+              goto trunc;
            ND_PRINT((ndo, "%s (0x%02x) ",
                   tok2str(rfc4675_tagged,"Unknown tag",*data),
                   *data));
@@ -547,7 +543,7 @@
         break;
    }
 
-   for (i=0; *data && i < length ; i++, data++)
+   for (i=0; i < length && *data; i++, data++)
        ND_PRINT((ndo, "%c", (*data < 32 || *data > 126) ? '.' : *data));
 
    return;
```
