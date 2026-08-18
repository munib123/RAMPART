# CrossVul Fix Pair: Improper Privilege Management in go
**Pair ID:** 25_1
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `25_1`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```go
Lines 1336-1376 of the vulnerable file.

			}
		}

		if compound {
			continue
		}

		/* No tags, then ignore it */
		if requiretags && f.Tag == "" {
			continue
		}

		/* Wrong field, skip it */
		if fname != field {
			continue
		}

		if checkperms {
			ok := true
			permstr := f.Tag.Get("pfset")
			ok, err = ctx.CheckPermsT("StructDetails("+fname+")", permstr)
			if !ok {
				return "", "", "", err
			}
		}

		return "string", fname, ToString(v.Interface()), nil
	}

	return "", "", "", nil
}

// StructDetails returns the details of a structure's field.
//
// It determines the type of the field and the string value of the field.
//
// The opts can be used to influence if permission checking needs to be done
// and if tags are required to be present for the field to be checked.
func StructDetails(ctx PfCtx, obj interface{}, field string, opts StructDetails_Options) (ftype string, fname string, fvalue string, err error) {
	field = strings.ToLower(field)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1353,6 +1353,7 @@
 		if checkperms {
 			ok := true
 			permstr := f.Tag.Get("pfset")
+
 			ok, err = ctx.CheckPermsT("StructDetails("+fname+")", permstr)
 			if !ok {
 				return "", "", "", err
@@ -1533,7 +1534,7 @@
 		}
 
 		set := f.Tag.Get(tag)
-		err = perms.FromString(set)
+		perms,err = FromString(set)
 		if err != nil {
 			return
 		}
```
