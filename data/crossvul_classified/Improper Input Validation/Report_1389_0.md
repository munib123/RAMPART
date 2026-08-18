# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1389_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1389_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1173-1213 of the vulnerable file.


static void
authorize_logger (const char *data)
{
  g_message ("%s", data);
}

static void
cockpit_auth_class_init (CockpitAuthClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = cockpit_auth_finalize;

  sig__idling = g_signal_new ("idling", COCKPIT_TYPE_AUTH, G_SIGNAL_RUN_FIRST,
                              0, NULL, NULL, NULL, G_TYPE_NONE, 0);

  cockpit_authorize_logger (authorize_logger, 0);
}

static char *
base64_decode_string (const char *enc)
{
  if (enc == NULL)
    return NULL;

  char *dec = g_strdup (enc);
  gsize len;
  g_base64_decode_inplace (dec, &len);
  dec[len] = '\0';
  return dec;
}

static CockpitSession *
session_for_headers (CockpitAuth *self,
                     const gchar *path,
                     GHashTable *in_headers)
{
  gchar *cookie = NULL;
  gchar *raw = NULL;
  const char *prefix = "v=2;k=";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1190,16 +1190,19 @@
   cockpit_authorize_logger (authorize_logger, 0);
 }
 
-static char *
+static gchar *
 base64_decode_string (const char *enc)
 {
+  gchar *dec;
+  gsize len;
+
   if (enc == NULL)
     return NULL;
 
-  char *dec = g_strdup (enc);
-  gsize len;
-  g_base64_decode_inplace (dec, &len);
-  dec[len] = '\0';
+  dec = (gchar *)g_base64_decode (enc, &len);
+  if (dec)
+    dec[len] = '\0';
+
   return dec;
 }
 
```
