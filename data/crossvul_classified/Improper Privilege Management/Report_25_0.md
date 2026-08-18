# CrossVul Fix Pair: Improper Privilege Management in go
**Pair ID:** 25_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `25_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```go
Lines 927-967 of the vulnerable file.

	/* Check all the prefixes */
	for _, n := range sys.sar_cache {
		if n.Contains(ctx.client_ip) {
			/* It is valid */
			return true
		}
	}

	/* Not in the SARestrict list */
	return false
}

// FromString can be used to parse a string into a Perm object.
//
// str can be in the formats:
//  perm1
//  perm1,perm2
//  perm1,perm2,perm3
//
// When an unknown permission is encountered, this function will return an error.
func (perm Perm) FromString(str string) (err error) {
	str = strings.ToLower(str)

	perm = PERM_NOTHING

	p := strings.Split(str, ",")
	for _, pm := range p {
		if pm == "" {
			continue
		}

		found := false
		var i uint
		i = 0
		for _, n := range permnames {
			if pm == n {
				perm += 1 << i
				found = true
				break
			}
			i++
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -944,7 +944,7 @@
 //  perm1,perm2,perm3
 //
 // When an unknown permission is encountered, this function will return an error.
-func (perm Perm) FromString(str string) (err error) {
+func FromString(str string) (perm Perm,err error) {
 	str = strings.ToLower(str)
 
 	perm = PERM_NOTHING
@@ -1332,7 +1332,7 @@
 func (ctx *PfCtxS) CheckPermsT(what string, permstr string) (ok bool, err error) {
 	var perms Perm
 
-	err = perms.FromString(permstr)
+	perms,err = FromString(permstr)
 	if err != nil {
 		return
 	}
```
