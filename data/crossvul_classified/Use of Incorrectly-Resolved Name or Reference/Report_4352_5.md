# CrossVul Fix Pair: Use of Incorrectly-Resolved Name or Reference in csharp
**Pair ID:** 4352_5
**Vulnerability Class:** Use of Incorrectly-Resolved Name or Reference
**CWE:** CWE-706
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4352_5`)

## Vulnerability Information & PoC

## Description
Use of Incorrectly-Resolved Name or Reference - The product uses a name or reference to access a resource, but the name/reference resolves to a resource that is outside of the intended control sphere.

## Vulnerable Code
```csharp
Lines 16-56 of the vulnerable file.


        #region EnvironmentBase

        public override void AddDirectoryToPath(string directoryPath, EnvironmentVariableTarget target)
        {
            throw new NotImplementedException();
        }

        public override void RemoveDirectoryFromPath(string directoryPath, EnvironmentVariableTarget target)
        {
            throw new NotImplementedException();
        }

        protected override string[] SplitPathVariable(string value)
        {
            return value.Split(':');
        }

        public override bool TryLocateExecutable(string program, out string path)
        {
            const string whichPath = "/usr/bin/which";
            var psi = new ProcessStartInfo(whichPath, program)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true
            };

            using (var where = new Process {StartInfo = psi})
            {
                where.Start();
                where.WaitForExit();

                switch (where.ExitCode)
                {
                    case 0: // found
                        string stdout = where.StandardOutput.ReadToEnd();
                        string[] results = stdout.Split(new[] {'\n'}, StringSplitOptions.RemoveEmptyEntries);
                        path = results.First();
                        return true;

                    case 1: // not found
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,6 +33,8 @@
 
         public override bool TryLocateExecutable(string program, out string path)
         {
+            // The "which" utility scans over the PATH and does not include the current working directory
+            // (unlike the equivalent "where.exe" on Windows), which is exactly what we want. Let's use it.
             const string whichPath = "/usr/bin/which";
             var psi = new ProcessStartInfo(whichPath, program)
             {
```
