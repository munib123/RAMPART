# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2640_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2640_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 134-174 of the vulnerable file.

	}
}
#define gethostbyaddr win32_gethostbyaddr
#endif /* _WIN32 */

struct h6namemem {
	struct in6_addr addr;
	char *name;
	struct h6namemem *nxt;
};

static struct h6namemem h6nametable[HASHNAMESIZE];

struct enamemem {
	u_short e_addr0;
	u_short e_addr1;
	u_short e_addr2;
	const char *e_name;
	u_char *e_nsap;			/* used only for nsaptable[] */
#define e_bs e_nsap			/* for bytestringtable */
	struct enamemem *e_nxt;
};

static struct enamemem enametable[HASHNAMESIZE];
static struct enamemem nsaptable[HASHNAMESIZE];
static struct enamemem bytestringtable[HASHNAMESIZE];

struct protoidmem {
	uint32_t p_oui;
	u_short p_proto;
	const char *p_name;
	struct protoidmem *p_nxt;
};

static struct protoidmem protoidtable[HASHNAMESIZE];

/*
 * A faster replacement for inet_ntoa().
 */
const char *
intoa(uint32_t addr)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -151,12 +151,24 @@
 	const char *e_name;
 	u_char *e_nsap;			/* used only for nsaptable[] */
 #define e_bs e_nsap			/* for bytestringtable */
+	size_t e_namelen;		/* for bytestringtable */
 	struct enamemem *e_nxt;
 };
 
 static struct enamemem enametable[HASHNAMESIZE];
 static struct enamemem nsaptable[HASHNAMESIZE];
-static struct enamemem bytestringtable[HASHNAMESIZE];
+
+struct bsnamemem {
+	u_short bs_addr0;
+	u_short bs_addr1;
+	u_short bs_addr2;
+	const char *bs_name;
+	u_char *bs_bytes;
+	unsigned int bs_nbytes;
+	struct bsnamemem *bs_nxt;
+};
+
+static struct bsnamemem bytestringtable[HASHNAMESIZE];
 
 struct protoidmem {
 	uint32_t p_oui;
@@ -380,11 +392,11 @@
  * with length 'nlen'
  */
 
-static inline struct enamemem *
+static inline struct bsnamemem *
 lookup_bytestring(netdissect_options *ndo, register const u_char *bs,
 		  const unsigned int nlen)
 {
-	struct enamemem *tp;
+	struct bsnamemem *tp;
 	register u_int i, j, k;
 
 	if (nlen >= 6) {
@@ -399,26 +411,28 @@
 		i = j = k = 0;
 
 	tp = &bytestringtable[(i ^ j) & (HASHNAMESIZE-1)];
-	while (tp->e_nxt)
-		if (tp->e_addr0 == i &&
-		    tp->e_addr1 == j &&
-		    tp->e_addr2 == k &&
-		    memcmp((const char *)bs, (const char *)(tp->e_bs), nlen) == 0)
+	while (tp->bs_nxt)
+		if (nlen == tp->bs_nbytes &&
+		    tp->bs_addr0 == i &&
+		    tp->bs_addr1 == j &&
+		    tp->bs_addr2 == k &&
+		    memcmp((const char *)bs, (const char *)(tp->bs_bytes), nlen) == 0)
 			return tp;
 		else
-			tp = tp->e_nxt;
-
-	tp->e_addr0 = i;
-	tp->e_addr1 = j;
-	tp->e_addr2 = k;
-
-	tp->e_bs = (u_char *) calloc(1, nlen + 1);
-	if (tp->e_bs == NULL)
+			tp = tp->bs_nxt;
+
+	tp->bs_addr0 = i;
+	tp->bs_addr1 = j;
+	tp->bs_addr2 = k;
+
+	tp->bs_bytes = (u_char *) calloc(1, nlen + 1);
+	if (tp->bs_bytes == NULL)
 		(*ndo->ndo_error)(ndo, "lookup_bytestring: calloc");
 
-	memcpy(tp->e_bs, bs, nlen);
-	tp->e_nxt = (struct enamemem *)calloc(1, sizeof(*tp));
-	if (tp->e_nxt == NULL)
+	memcpy(tp->bs_bytes, bs, nlen);
+	tp->bs_nbytes = nlen;
+	tp->bs_nxt = (struct bsnamemem *)calloc(1, sizeof(*tp));
+	if (tp->bs_nxt == NULL)
 		(*ndo->ndo_error)(ndo, "lookup_bytestring: calloc");
 
 	return tp;
@@ -549,12 +563,12 @@
 	const unsigned int len = 8;
 	register u_int i;
 	register char *cp;
-	register struct enamemem *tp;
+	register struct bsnamemem *tp;
 	char buf[BUFSIZE];
 
 	tp = lookup_bytestring(ndo, ep, len);
-	if (tp->e_name)
-		return (tp->e_name);
+	if (tp->bs_name)
+		return (tp->bs_name);
 
 	cp = buf;
 	for (i = len; i > 0 ; --i) {
@@ -566,11 +580,11 @@
 
 	*cp = '\0';
 
-	tp->e_name = strdup(buf);
-	if (tp->e_name == NULL)
+	tp->bs_name = strdup(buf);
+	if (tp->bs_name == NULL)
 		(*ndo->ndo_error)(ndo, "le64addr_string: strdup(buf)");
 
-	return (tp->e_name);
+	return (tp->bs_name);
 }
 
 const char *
@@ -579,7 +593,7 @@
 {
 	register u_int i;
 	register char *cp;
-	register struct enamemem *tp;
+	register struct bsnamemem *tp;
 
 	if (len == 0)
 		return ("<empty>");
@@ -591,11 +605,11 @@
 		return (q922_string(ndo, ep, len));
 
 	tp = lookup_bytestring(ndo, ep, len);
-	if (tp->e_name)
-		return (tp->e_name);
-
-	tp->e_name = cp = (char *)malloc(len*3);
-	if (tp->e_name == NULL)
+	if (tp->bs_name)
+		return (tp->bs_name);
+
+	tp->bs_name = cp = (char *)malloc(len*3);
+	if (tp->bs_name == NULL)
 		(*ndo->ndo_error)(ndo, "linkaddr_string: malloc");
 	*cp++ = hex[*ep >> 4];
 	*cp++ = hex[*ep++ & 0xf];
@@ -605,7 +619,7 @@
 		*cp++ = hex[*ep++ & 0xf];
 	}
 	*cp = '\0';
-	return (tp->e_name);
+	return (tp->bs_name);
 }
 
 const char *
```
