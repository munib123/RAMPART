# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in javascript
**Pair ID:** 774_6
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `774_6`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```javascript
Lines 9-49 of the vulnerable file.

  checkingManifest: 'Validating package.json',
  fetchingPackages: 'Fetching packages',
  linkingDependencies: 'Linking dependencies',
  rebuildingPackages: 'Rebuilding all packages',
  buildingFreshPackages: 'Building fresh packages',
  cleaningModules: 'Cleaning modules',
  bumpingVersion: 'Bumping version',
  savingHar: 'Saving HAR file: $0',
  answer: 'Answer?',
  usage: 'Usage',
  installCommandRenamed: '`install` has been replaced with `add` to add new dependencies. Run $0 instead.',
  globalFlagRemoved: '`--global` has been deprecated. Please run $0 instead.',
  waitingInstance: 'Waiting for the other yarn instance to finish (pid $0, inside $1)',
  waitingNamedInstance: 'Waiting for the other yarn instance to finish ($0)',
  offlineRetrying: 'There appears to be trouble with your network connection. Retrying...',
  internalServerErrorRetrying: 'There appears to be trouble with the npm registry (returned $1). Retrying...',
  clearedCache: 'Cleared cache.',
  couldntClearPackageFromCache: "Couldn't clear package $0 from cache",
  clearedPackageFromCache: 'Cleared package $0 from cache',
  packWroteTarball: 'Wrote tarball to $0.',

  helpExamples: '  Examples:\n$0\n',
  helpCommands: '  Commands:\n$0\n',
  helpCommandsMore: '  Run `$0` for more information on specific commands.',
  helpLearnMore: '  Visit $0 to learn more about Yarn.\n',

  manifestPotentialTypo: 'Potential typo $0, did you mean $1?',
  manifestBuiltinModule: '$0 is also the name of a node core module',
  manifestNameDot: "Name can't start with a dot",
  manifestNameIllegalChars: 'Name contains illegal characters',
  manifestNameBlacklisted: 'Name is blacklisted',
  manifestLicenseInvalid: 'License should be a valid SPDX license expression',
  manifestLicenseNone: 'No license field',
  manifestStringExpected: '$0 is not a string',
  manifestDependencyCollision:
    '$0 has dependency $1 with range $2 that collides with a dependency in $3 of the same name with version $4',
  manifestDirectoryNotFound: 'Unable to read $0 directory of module $1',

  verboseFileCopy: 'Copying $0 to $1.',
  verboseFileLink: 'Creating hardlink at $0 to $1.',
  verboseFileSymlink: 'Creating symlink at $0 to $1.',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,8 @@
   couldntClearPackageFromCache: "Couldn't clear package $0 from cache",
   clearedPackageFromCache: 'Cleared package $0 from cache',
   packWroteTarball: 'Wrote tarball to $0.',
-
+  invalidBinField: 'Invalid bin field for $0.',
+  invalidBinEntry: 'Invalid bin entry for $1 (in $0).',
   helpExamples: '  Examples:\n$0\n',
   helpCommands: '  Commands:\n$0\n',
   helpCommandsMore: '  Run `$0` for more information on specific commands.',
```
