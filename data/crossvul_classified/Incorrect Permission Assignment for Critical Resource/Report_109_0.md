# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in go
**Pair ID:** 109_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `109_0`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```go
Lines 371-411 of the vulnerable file.

	return nil
}

func addRlimits(config *CreateConfig, g *generate.Generator) error {
	var (
		ul  *units.Ulimit
		err error
	)

	for _, u := range config.Resources.Ulimit {
		if ul, err = units.ParseUlimit(u); err != nil {
			return errors.Wrapf(err, "ulimit option %q requires name=SOFT:HARD, failed to be parsed", u)
		}

		g.AddProcessRlimits("RLIMIT_"+strings.ToUpper(ul.Name), uint64(ul.Hard), uint64(ul.Soft))
	}
	return nil
}

func setupCapabilities(config *CreateConfig, configSpec *spec.Spec) error {
	var err error
	var caplist []string
	caplist, err = caps.TweakCapabilities(configSpec.Process.Capabilities.Bounding, config.CapAdd, config.CapDrop)
	if err != nil {
		return err
	}

	configSpec.Process.Capabilities.Bounding = caplist
	configSpec.Process.Capabilities.Permitted = caplist
	configSpec.Process.Capabilities.Inheritable = caplist
	configSpec.Process.Capabilities.Effective = caplist
	return nil
}

func addDevice(g *generate.Generator, device string) error {
	dev, err := devices.DeviceFromPath(device, "rwm")
	if err != nil {
		return errors.Wrapf(err, "%s is not a valid device", device)
	}
	linuxdev := spec.LinuxDevice{
		Path:     dev.Path,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -388,8 +388,19 @@
 }
 
 func setupCapabilities(config *CreateConfig, configSpec *spec.Spec) error {
+	useNotRoot := func(user string) bool {
+		if user == "" || user == "root" || user == "0" {
+			return false
+		}
+		return true
+	}
+
 	var err error
 	var caplist []string
+	bounding := configSpec.Process.Capabilities.Bounding
+	if useNotRoot(config.User) {
+		configSpec.Process.Capabilities.Bounding = caplist
+	}
 	caplist, err = caps.TweakCapabilities(configSpec.Process.Capabilities.Bounding, config.CapAdd, config.CapDrop)
 	if err != nil {
 		return err
@@ -399,6 +410,14 @@
 	configSpec.Process.Capabilities.Permitted = caplist
 	configSpec.Process.Capabilities.Inheritable = caplist
 	configSpec.Process.Capabilities.Effective = caplist
+	configSpec.Process.Capabilities.Ambient = caplist
+	if useNotRoot(config.User) {
+		caplist, err = caps.TweakCapabilities(bounding, config.CapAdd, config.CapDrop)
+		if err != nil {
+			return err
+		}
+	}
+	configSpec.Process.Capabilities.Bounding = caplist
 	return nil
 }
 
```
