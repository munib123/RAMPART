# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 5867_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5867_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 8-48 of the vulnerable file.

 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef __APPLE__
#define __AVAILABILITYMACROS__
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#endif

#include "inet.h"				  /* make it first to avoid macro redefinitions */
#include <openssl/ssl.h>		  /* SSL_() */
#include <openssl/err.h>		  /* ERR_() */
#ifdef WIN32
#include <openssl/rand.h>		  /* RAND_seed() */
#endif
#include "../../config.h"
#include <time.h>				  /* asctime() */
#include <string.h>				  /* strncpy() */
#include "ssl.h"				  /* struct cert_info */

#include <glib.h>
#include <glib/gprintf.h>
#include "util.h"

/* If openssl was built without ec */
#ifndef SSL_OP_SINGLE_ECDH_USE
#define SSL_OP_SINGLE_ECDH_USE 0
#endif

/* globals */
static struct chiper_info chiper_info;		/* static buffer for _SSL_get_cipher_info() */
static char err_buf[256];			/* generic error buffer */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,6 +25,7 @@
 #include "inet.h"				  /* make it first to avoid macro redefinitions */
 #include <openssl/ssl.h>		  /* SSL_() */
 #include <openssl/err.h>		  /* ERR_() */
+#include <openssl/x509v3.h>
 #ifdef WIN32
 #include <openssl/rand.h>		  /* RAND_seed() */
 #endif
@@ -35,6 +36,7 @@
 
 #include <glib.h>
 #include <glib/gprintf.h>
+#include <gio/gio.h>
 #include "util.h"
 
 /* If openssl was built without ec */
@@ -339,3 +341,204 @@
 	SSL_free (ssl);
 	ERR_remove_state (0);		  /* free state buffer */
 }
+
+/* Hostname validation code based on OpenBSD's libtls. */
+
+static int
+_SSL_match_hostname (const char *cert_hostname, const char *hostname)
+{
+	const char *cert_domain, *domain, *next_dot;
+
+	if (g_ascii_strcasecmp (cert_hostname, hostname) == 0)
+		return 0;
+
+	/* Wildcard match? */
+	if (cert_hostname[0] == '*')
+	{
+		/*
+		 * Valid wildcards:
+		 * - "*.domain.tld"
+		 * - "*.sub.domain.tld"
+		 * - etc.
+		 * Reject "*.tld".
+		 * No attempt to prevent the use of eg. "*.co.uk".
+		 */
+		cert_domain = &cert_hostname[1];
+		/* Disallow "*"  */
+		if (cert_domain[0] == '\0')
+			return -1;
+		/* Disallow "*foo" */
+		if (cert_domain[0] != '.')
+			return -1;
+		/* Disallow "*.." */
+		if (cert_domain[1] == '.')
+			return -1;
+		next_dot = strchr (&cert_domain[1], '.');
+		/* Disallow "*.bar" */
+		if (next_dot == NULL)
+			return -1;
+		/* Disallow "*.bar.." */
+		if (next_dot[1] == '.')
+			return -1;
+
+		domain = strchr (hostname, '.');
+
+		/* No wildcard match against a hostname with no domain part. */
+		if (domain == NULL || strlen(domain) == 1)
+			return -1;
+
+		if (g_ascii_strcasecmp (cert_domain, domain) == 0)
+			return 0;
+	}
+
+	return -1;
+}
+
+static int
+_SSL_check_subject_altname (X509 *cert, const char *host)
+{
+	STACK_OF(GENERAL_NAME) *altname_stack = NULL;
+	GInetAddress *addr;
+	GSocketFamily family;
+	int type = GEN_DNS;
+	int count, i;
+	int rv = -1;
+
+	altname_stack = X509_get_ext_d2i (cert, NID_subject_alt_name, NULL, NULL);
+	if (altname_stack == NULL)
+		return -1;
+
+	addr = g_inet_address_new_from_string (host);
+	if (addr != NULL)
+	{
+		family = g_inet_address_get_family (addr);
+		if (family == G_SOCKET_FAMILY_IPV4 || family == G_SOCKET_FAMILY_IPV6)
+			type = GEN_IPADD;
+	}
+
+	count = sk_GENERAL_NAME_num(altname_stack);
+	for (i = 0; i < count; i++)
+	{
+		GENERAL_NAME *altname;
+
+		altname = sk_GENERAL_NAME_value (altname_stack, i);
+
+		if (altname->type != type)
+			continue;
+
+		if (type == GEN_DNS)
+		{
+			unsigned char *data;
+			int format;
+
+			format = ASN1_STRING_type (altname->d.dNSName);
+			if (format == V_ASN1_IA5STRING)
+			{
+				data = ASN1_STRING_data (altname->d.dNSName);
+
+				if (ASN1_STRING_length (altname->d.dNSName) != (int)strlen(data))
+				{
+					g_warning("NUL byte in subjectAltName, probably a malicious certificate.\n");
+					rv = -2;
+					break;
+				}
+
+				if (_SSL_match_hostname (data, host) == 0)
+				{
+					rv = 0;
+					break;
+				}
+			}
+			else
+				g_warning ("unhandled subjectAltName dNSName encoding (%d)\n", format);
+
+		}
+		else if (type == GEN_IPADD)
+		{
+			unsigned char *data;
+			const guint8 *addr_bytes;
+			int datalen, addr_len;
+
+			datalen = ASN1_STRING_length (altname->d.iPAddress);
+			data = ASN1_STRING_data (altname->d.iPAddress);
+
+			addr_bytes = g_inet_address_to_bytes (addr);
+			addr_len = (int)g_inet_address_get_native_size (addr);
+
+			if (datalen == addr_len && memcmp (data, addr_bytes, addr_len) == 0)
+			{
+				rv = 0;
+				break;
+			}
+		}
+	}
+
+	if (addr != NULL)
+		g_object_unref (addr);
+	sk_GENERAL_NAME_free (altname_stack);
+	return rv;
+}
+
+static int
+_SSL_check_common_name (X509 *cert, const char *host)
+{
+	X509_NAME *name;
+	char *common_name = NULL;
+	int common_name_len;
+	int rv = -1;
+	GInetAddress *addr;
+
+	name = X509_get_subject_name (cert);
+	if (name == NULL)
+		return -1;
+
+	common_name_len = X509_NAME_get_text_by_NID (name, NID_commonName, NULL, 0);
+	if (common_name_len < 0)
+		return -1;
+
+	common_name = calloc (common_name_len + 1, 1);
+	if (common_name == NULL)
+		return -1;
+
+	X509_NAME_get_text_by_NID (name, NID_commonName, common_name, common_name_len + 1);
+
+	/* NUL bytes in CN? */
+	if (common_name_len != (int)strlen(common_name))
+	{
+		g_warning ("NUL byte in Common Name field, probably a malicious certificate.\n");
+		rv = -2;
+		goto out;
+	}
+
+	if ((addr = g_inet_address_new_from_string (host)) != NULL)
+	{
+		/*
+		 * We don't want to attempt wildcard matching against IP
+		 * addresses, so perform a simple comparison here.
+		 */
+		if (g_strcmp0 (common_name, host) == 0)
+			rv = 0;
+		else
+			rv = -1;
+
+		g_object_unref (addr);
+	}
+	else if (_SSL_match_hostname (common_name, host) == 0)
+		rv = 0;
+
+out:
+	free(common_name);
+	return rv;
+}
+
+int
+_SSL_check_hostname (X509 *cert, const char *host)
+{
+	int rv;
+
+	rv = _SSL_check_subject_altname (cert, host);
+	if (rv == 0 || rv == -2)
+		return rv;
+
+	return _SSL_check_common_name (cert, host);
+}
```
