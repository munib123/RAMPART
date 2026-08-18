# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in go
**Pair ID:** 1201_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1201_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```go
Lines 35-75 of the vulnerable file.

  You can copy from the container's file system to the local machine or the reverse, from the local filesystem to the container. If "-" is specified for either the SRC_PATH or DEST_PATH, you can also stream a tar archive from STDIN or to STDOUT. The CONTAINER can be a running or stopped container.  The SRC_PATH or DEST_PATH can be a file or directory.
`
	_cpCommand = &cobra.Command{
		Use:   "cp [flags] SRC_PATH DEST_PATH",
		Short: "Copy files/folders between a container and the local filesystem",
		Long:  cpDescription,
		RunE: func(cmd *cobra.Command, args []string) error {
			cpCommand.InputArgs = args
			cpCommand.GlobalFlags = MainGlobalOpts
			cpCommand.Remote = remoteclient
			return cpCmd(&cpCommand)
		},
		Example: "[CONTAINER:]SRC_PATH [CONTAINER:]DEST_PATH",
	}
)

func init() {
	cpCommand.Command = _cpCommand
	flags := cpCommand.Flags()
	flags.BoolVar(&cpCommand.Extract, "extract", false, "Extract the tar file into the destination directory.")
	flags.BoolVar(&cpCommand.Pause, "pause", false, "Pause the container while copying")
	cpCommand.SetHelpTemplate(HelpTemplate())
	cpCommand.SetUsageTemplate(UsageTemplate())
}

func cpCmd(c *cliconfig.CpValues) error {
	args := c.InputArgs
	if len(args) != 2 {
		return errors.Errorf("you must provide a source path and a destination path")
	}

	runtime, err := libpodruntime.GetRuntime(getContext(), &c.PodmanCommand)
	if err != nil {
		return errors.Wrapf(err, "could not get runtime")
	}
	defer runtime.DeferredShutdown(false)

	return copyBetweenHostAndContainer(runtime, args[0], args[1], c.Extract, c.Pause)
}

func copyBetweenHostAndContainer(runtime *libpod.Runtime, src string, dest string, extract bool, pause bool) error {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,7 +52,7 @@
 	cpCommand.Command = _cpCommand
 	flags := cpCommand.Flags()
 	flags.BoolVar(&cpCommand.Extract, "extract", false, "Extract the tar file into the destination directory.")
-	flags.BoolVar(&cpCommand.Pause, "pause", false, "Pause the container while copying")
+	flags.BoolVar(&cpCommand.Pause, "pause", true, "Pause the container while copying")
 	cpCommand.SetHelpTemplate(HelpTemplate())
 	cpCommand.SetUsageTemplate(UsageTemplate())
 }
@@ -147,7 +147,6 @@
 
 	hostOwner := idtools.IDPair{UID: int(hostUID), GID: int(hostGID)}
 
-	var glob []string
 	if isFromHostToCtr {
 		if isVol, volDestName, volName := isVolumeDestName(destPath, ctr); isVol {
 			path, err := pathWithVolumeMount(ctr, runtime, volDestName, volName, destPath)
@@ -209,13 +208,7 @@
 			srcPath = cleanedPath
 		}
 	}
-	glob, err = filepath.Glob(srcPath)
-	if err != nil {
-		return errors.Wrapf(err, "invalid glob %q", srcPath)
-	}
-	if len(glob) == 0 {
-		glob = append(glob, srcPath)
-	}
+
 	if !filepath.IsAbs(destPath) {
 		dir, err := os.Getwd()
 		if err != nil {
@@ -224,19 +217,11 @@
 		destPath = filepath.Join(dir, destPath)
 	}
 
-	var lastError error
-	for _, src := range glob {
-		if src == "-" {
-			src = os.Stdin.Name()
-			extract = true
-		}
-		err := copy(src, destPath, dest, idMappingOpts, &destOwner, extract, isFromHostToCtr)
-		if lastError != nil {
-			logrus.Error(lastError)
-		}
-		lastError = err
-	}
-	return lastError
+	if src == "-" {
+		srcPath = os.Stdin.Name()
+		extract = true
+	}
+	return copy(srcPath, destPath, dest, idMappingOpts, &destOwner, extract, isFromHostToCtr)
 }
 
 func getUser(mountPoint string, userspec string) (specs.User, error) {
```
