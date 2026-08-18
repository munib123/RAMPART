# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in go
**Pair ID:** 5015_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5015_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```go
Lines 218-258 of the vulnerable file.


	return GetExecUser(userSpec, defaults, passwd, group)
}

// GetExecUser parses a user specification string (using the passwd and group
// readers as sources for /etc/passwd and /etc/group data, respectively). In
// the case of blank fields or missing data from the sources, the values in
// defaults is used.
//
// GetExecUser will return an error if a user or group literal could not be
// found in any entry in passwd and group respectively.
//
// Examples of valid user specifications are:
//     * ""
//     * "user"
//     * "uid"
//     * "user:group"
//     * "uid:gid
//     * "user:gid"
//     * "uid:group"
func GetExecUser(userSpec string, defaults *ExecUser, passwd, group io.Reader) (*ExecUser, error) {
	var (
		userArg, groupArg string
		name              string
	)

	if defaults == nil {
		defaults = new(ExecUser)
	}

	// Copy over defaults.
	user := &ExecUser{
		Uid:   defaults.Uid,
		Gid:   defaults.Gid,
		Sgids: defaults.Sgids,
		Home:  defaults.Home,
	}

	// Sgids slice *cannot* be nil.
	if user.Sgids == nil {
		user.Sgids = []int{}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -235,10 +235,14 @@
 //     * "uid:gid
 //     * "user:gid"
 //     * "uid:group"
+//
+// It should be noted that if you specify a numeric user or group id, they will
+// not be evaluated as usernames (only the metadata will be filled). So attempting
+// to parse a user with user.Name = "1337" will produce the user with a UID of
+// 1337.
 func GetExecUser(userSpec string, defaults *ExecUser, passwd, group io.Reader) (*ExecUser, error) {
 	var (
 		userArg, groupArg string
-		name              string
 	)
 
 	if defaults == nil {
@@ -261,11 +265,22 @@
 	// allow for userArg to have either "user" syntax, or optionally "user:group" syntax
 	parseLine(userSpec, &userArg, &groupArg)
 
+	// Convert userArg and groupArg to be numeric, so we don't have to execute
+	// Atoi *twice* for each iteration over lines.
+	uidArg, uidErr := strconv.Atoi(userArg)
+	gidArg, gidErr := strconv.Atoi(groupArg)
+
 	users, err := ParsePasswdFilter(passwd, func(u User) bool {
 		if userArg == "" {
 			return u.Uid == user.Uid
 		}
-		return u.Name == userArg || strconv.Itoa(u.Uid) == userArg
+
+		if uidErr == nil {
+			// If the userArg is numeric, always treat it as a UID.
+			return uidArg == u.Uid
+		}
+
+		return u.Name == userArg
 	})
 	if err != nil && passwd != nil {
 		if userArg == "" {
@@ -274,47 +289,55 @@
 		return nil, fmt.Errorf("Unable to find user %v: %v", userArg, err)
 	}
 
-	haveUser := users != nil && len(users) > 0
-	if haveUser {
-		// if we found any user entries that matched our filter, let's take the first one as "correct"
-		name = users[0].Name
+	var matchedUserName string
+	if len(users) > 0 {
+		// First match wins, even if there's more than one matching entry.
+		matchedUserName = users[0].Name
 		user.Uid = users[0].Uid
 		user.Gid = users[0].Gid
 		user.Home = users[0].Home
 	} else if userArg != "" {
-		// we asked for a user but didn't find them...  let's check to see if we wanted a numeric user
-		user.Uid, err = strconv.Atoi(userArg)
-		if err != nil {
-			// not numeric - we have to bail
-			return nil, fmt.Errorf("Unable to find user %v", userArg)
-		}
+		// If we can't find a user with the given username, the only other valid
+		// option is if it's a numeric username with no associated entry in passwd.
+
+		if uidErr != nil {
+			// Not numeric.
+			return nil, fmt.Errorf("unable to find user %s: %v", userArg, ErrNoPasswdEntries)
+		}
+		user.Uid = uidArg
 
 		// Must be inside valid uid range.
 		if user.Uid < minId || user.Uid > maxId {
 			return nil, ErrRange
 		}
 
-		// if userArg couldn't be found in /etc/passwd but is numeric, just roll with it - this is legit
-	}
-
-	if groupArg != "" || name != "" {
+		// Okay, so it's numeric. We can just roll with this.
+	}
+
+	// On to the groups. If we matched a username, we need to do this because of
+	// the supplementary group IDs.
+	if groupArg != "" || matchedUserName != "" {
 		groups, err := ParseGroupFilter(group, func(g Group) bool {
-			// Explicit group format takes precedence.
-			if groupArg != "" {
-				return g.Name == groupArg || strconv.Itoa(g.Gid) == groupArg
-			}
-
-			// Check if user is a member.
-			for _, u := range g.List {
-				if u == name {
-					return true
+			// If the group argument isn't explicit, we'll just search for it.
+			if groupArg == "" {
+				// Check if user is a member of this group.
+				for _, u := range g.List {
+					if u == matchedUserName {
+						return true
+					}
 				}
-			}
-
-			return false
+				return false
+			}
+
+			if gidErr == nil {
+				// If the groupArg is numeric, always treat it as a GID.
+				return gidArg == g.Gid
+			}
+
+			return g.Name == groupArg
 		})
 		if err != nil && group != nil {
-			return nil, fmt.Errorf("Unable to find groups for user %v: %v", users[0].Name, err)
+			return nil, fmt.Errorf("unable to find groups for spec %v: %v", matchedUserName, err)
 		}
 
 		haveGroup := groups != nil && len(groups) > 0
@@ -322,23 +345,25 @@
 			if haveGroup {
 				// if we found any group entries that matched our filter, let's take the first one as "correct"
 				user.Gid = groups[0].Gid
-			} else {
-				// we asked for a group but didn't find id...  let's check to see if we wanted a numeric group
-				user.Gid, err = strconv.Atoi(groupArg)
-				if err != nil {
-					// not numeric - we have to bail
-					return nil, fmt.Errorf("Unable to find group %v", groupArg)
+			} else if groupArg != "" {
+				// If we can't find a group with the given name, the only other valid
+				// option is if it's a numeric group name with no associated entry in group.
+
+				if gidErr != nil {
+					// Not numeric.
+					return nil, fmt.Errorf("unable to find group %s: %v", groupArg, ErrNoGroupEntries)
 				}
+				user.Gid = gidArg
 
 				// Ensure gid is inside gid range.
 				if user.Gid < minId || user.Gid > maxId {
 					return nil, ErrRange
 				}
 
-				// if groupArg couldn't be found in /etc/group but is numeric, just roll with it - this is legit
-			}
-		} else if haveGroup {
-			// If implicit group format, fill supplementary gids.
+				// Okay, so it's numeric. We can just roll with this.
+			}
+		} else if len(groups) > 0 {
+			// Supplementary group ids only make sense if in the implicit form.
 			user.Sgids = make([]int, len(groups))
 			for i, group := range groups {
 				user.Sgids[i] = group.Gid
```
