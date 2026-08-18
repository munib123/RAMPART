# CrossVul Fix Pair: Use of Multiple Resources with Duplicate Identifier in go
**Pair ID:** 4142_2
**Vulnerability Class:** Use of Multiple Resources with Duplicate Identifier
**CWE:** CWE-694
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4142_2`)

## Vulnerability Information & PoC

## Description
Use of Multiple Resources with Duplicate Identifier - If the product assumes that each resource has a unique identifier, the product could operate on the wrong resource if attackers can cause multiple resources to be associated with the same identifier.

## Vulnerable Code
```go
Lines 79-119 of the vulnerable file.

	// - If both OS and Arch match the current platform, search will stop and the command will be executed
	// - If OS matches and there is no more specific match, the command will be executed
	// - If no OS/Arch match is found, the default command will be executed
	// - If no command is present and no matches are found in platformCommand, Helm will exit with an error
	PlatformCommand []PlatformCommand `json:"platformCommand"`
	Command         string            `json:"command"`

	// IgnoreFlags ignores any flags passed in from Helm
	//
	// For example, if the plugin is invoked as `helm --debug myplugin`, if this
	// is false, `--debug` will be appended to `--command`. If this is true,
	// the `--debug` flag will be discarded.
	IgnoreFlags bool `json:"ignoreFlags"`

	// Hooks are commands that will run on events.
	Hooks Hooks

	// Downloaders field is used if the plugin supply downloader mechanism
	// for special protocols.
	Downloaders []Downloaders `json:"downloaders"`
}

// Plugin represents a plugin.
type Plugin struct {
	// Metadata is a parsed representation of a plugin.yaml
	Metadata *Metadata
	// Dir is the string path to the directory that holds the plugin.
	Dir string
}

// The following rules will apply to processing the Plugin.PlatformCommand.Command:
// - If both OS and Arch match the current platform, search will stop and the command will be prepared for execution
// - If OS matches and there is no more specific match, the command will be prepared for execution
// - If no OS/Arch match is found, return nil
func getPlatformCommand(cmds []PlatformCommand) []string {
	var command []string
	eq := strings.EqualFold
	for _, c := range cmds {
		if eq(c.OperatingSystem, runtime.GOOS) {
			command = strings.Split(os.ExpandEnv(c.Command), " ")
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -96,6 +96,12 @@
 	// Downloaders field is used if the plugin supply downloader mechanism
 	// for special protocols.
 	Downloaders []Downloaders `json:"downloaders"`
+
+	// UseTunnelDeprecated indicates that this command needs a tunnel.
+	// Setting this will cause a number of side effects, such as the
+	// automatic setting of HELM_HOST.
+	// DEPRECATED and unused, but retained for backwards compatibility with Helm 2 plugins. Remove in Helm 4
+	UseTunnelDeprecated bool `json:"useTunnel,omitempty"`
 }
 
 // Plugin represents a plugin.
@@ -200,7 +206,7 @@
 	}
 
 	plug := &Plugin{Dir: dirname}
-	if err := yaml.Unmarshal(data, &plug.Metadata); err != nil {
+	if err := yaml.UnmarshalStrict(data, &plug.Metadata); err != nil {
 		return nil, errors.Wrapf(err, "failed to load plugin at %q", pluginfile)
 	}
 	return plug, validatePluginData(plug, pluginfile)
```
