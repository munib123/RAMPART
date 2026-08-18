# CrossVul Fix Pair: Reliance on Reverse DNS Resolution for a Security-Critical Action in go
**Pair ID:** 3948_1
**Vulnerability Class:** Reliance on Reverse DNS Resolution for a Security-Critical Action
**CWE:** CWE-350
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3948_1`)

## Vulnerability Information & PoC

## Description
Reliance on Reverse DNS Resolution for a Security-Critical Action - Since DNS names can be easily spoofed or misreported, and it may be difficult for the product to detect if a trusted DNS server has been compromised, DNS names do not constitute a valid authenticat...

## Vulnerable Code
```go
Lines 38-63 of the vulnerable file.

		link, err := netlink.LinkByName(ifName)
		if err != nil {
			if err.Error() == errors.New("Link not found").Error() {
				return ErrLinkNotFound
			}
			return err
		}
		return work(link)
	})
}

func WithNetNSByPath(path string, work func() error) error {
	ns, err := netns.GetFromPath(path)
	if err != nil {
		return err
	}
	return WithNetNS(ns, work)
}

func NSPathByPid(pid int) string {
	return NSPathByPidWithRoot("/", pid)
}

func NSPathByPidWithRoot(root string, pid int) string {
	return filepath.Join(root, fmt.Sprintf("/proc/%d/ns/net", pid))
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,9 +55,9 @@
 }
 
 func NSPathByPid(pid int) string {
-	return NSPathByPidWithRoot("/", pid)
+	return NSPathByPidWithProc("/proc", pid)
 }
 
-func NSPathByPidWithRoot(root string, pid int) string {
-	return filepath.Join(root, fmt.Sprintf("/proc/%d/ns/net", pid))
+func NSPathByPidWithProc(procPath string, pid int) string {
+	return filepath.Join(procPath, fmt.Sprint(pid), "/ns/net")
 }
```
