# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4840_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4840_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 3158-3198 of the vulnerable file.

evdns_search_ndots_set(const int ndots) {
	evdns_base_search_ndots_set(current_base, ndots);
}

static void
search_set_from_hostname(struct evdns_base *base) {
	char hostname[HOST_NAME_MAX + 1], *domainname;

	ASSERT_LOCKED(base);
	search_postfix_clear(base);
	if (gethostname(hostname, sizeof(hostname))) return;
	domainname = strchr(hostname, '.');
	if (!domainname) return;
	search_postfix_add(base, domainname);
}

/* warning: returns malloced string */
static char *
search_make_new(const struct search_state *const state, int n, const char *const base_name) {
	const size_t base_len = strlen(base_name);
	const char need_to_append_dot = base_name[base_len - 1] == '.' ? 0 : 1;
	struct search_domain *dom;

	for (dom = state->head; dom; dom = dom->next) {
		if (!n--) {
			/* this is the postfix we want */
			/* the actual postfix string is kept at the end of the structure */
			const u8 *const postfix = ((u8 *) dom) + sizeof(struct search_domain);
			const int postfix_len = dom->len;
			char *const newname = (char *) mm_malloc(base_len + need_to_append_dot + postfix_len + 1);
			if (!newname) return NULL;
			memcpy(newname, base_name, base_len);
			if (need_to_append_dot) newname[base_len] = '.';
			memcpy(newname + base_len + need_to_append_dot, postfix, postfix_len);
			newname[base_len + need_to_append_dot + postfix_len] = 0;
			return newname;
		}
	}

	/* we ran off the end of the list and still didn't find the requested string */
	EVUTIL_ASSERT(0);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3175,8 +3175,11 @@
 static char *
 search_make_new(const struct search_state *const state, int n, const char *const base_name) {
 	const size_t base_len = strlen(base_name);
-	const char need_to_append_dot = base_name[base_len - 1] == '.' ? 0 : 1;
+	char need_to_append_dot;
 	struct search_domain *dom;
+
+	if (!base_len) return NULL;
+	need_to_append_dot = base_name[base_len - 1] == '.' ? 0 : 1;
 
 	for (dom = state->head; dom; dom = dom->next) {
 		if (!n--) {
```
