# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in java
**Pair ID:** 2469_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2469_0`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```java
Lines 53-93 of the vulnerable file.


	// filled by spring (perun-core.xml)
	public static PerunBlImpl setPerunBlImpl(PerunBlImpl perun) {
		perunBl = perun;
		return perun;
	}

	@Override
	public List<Map<String,String>> findSubjectsLogins(String searchString) throws InternalErrorException {
		return findSubjectsLogins(searchString, 0);
	}

	@Override
	public List<Map<String,String>> findSubjectsLogins(String searchString, int maxResults) throws InternalErrorException {
		// Prepare searchQuery
		// attributes.get("query") contains query template, e.g. (uid=?), ? will be replaced by the searchString
		String query = getAttributes().get("query");
		if (query == null) {
			throw new InternalErrorException("query attributes is required");
		}
		query = query.replaceAll("\\?", searchString);

		String base = getAttributes().get("base");
		if (base == null) {
			throw new InternalErrorException("base attributes is required");
		}
		return this.querySource(query, base, maxResults);
	}

	@Override
	public Map<String, String> getSubjectByLogin(String login) throws InternalErrorException, SubjectNotExistsException {
		// Prepare searchQuery
		// attributes.get("loginQuery") contains query template, e.g. (uid=?), ? will be replaced by the login
		String query = getAttributes().get("loginQuery");
		if (query == null) {
			throw new InternalErrorException("loginQuery attributes is required");
		}
		query = query.replaceAll("\\?", login);

		String base = getAttributes().get("base");
		if (base == null) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -70,7 +70,7 @@
 		if (query == null) {
 			throw new InternalErrorException("query attributes is required");
 		}
-		query = query.replaceAll("\\?", searchString);
+		query = query.replace("?", Utils.escapeStringForLDAP(searchString));
 
 		String base = getAttributes().get("base");
 		if (base == null) {
@@ -87,7 +87,7 @@
 		if (query == null) {
 			throw new InternalErrorException("loginQuery attributes is required");
 		}
-		query = query.replaceAll("\\?", login);
+		query = query.replace("?", Utils.escapeStringForLDAP(login));
 
 		String base = getAttributes().get("base");
 		if (base == null) {
```
