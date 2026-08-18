# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 2141_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2141_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 32-72 of the vulnerable file.

    def __init__(self, filename=C.DEFAULT_HOST_LIST):

        # Support inventory scripts that are not prefixed with some
        # path information but happen to be in the current working
        # directory when '.' is not in PATH.
        self.filename = os.path.abspath(filename)
        cmd = [ self.filename, "--list" ]
        try:
            sp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError, e:
            raise errors.AnsibleError("problem running %s (%s)" % (' '.join(cmd), e))
        (stdout, stderr) = sp.communicate()
        self.data = stdout
        # see comment about _meta below
        self.host_vars_from_top = None
        self.groups = self._parse(stderr)

    def _parse(self, err):

        all_hosts = {}
        self.raw  = utils.parse_json(self.data)
        all       = Group('all')
        groups    = dict(all=all)
        group     = None


        if 'failed' in self.raw:
            sys.stderr.write(err + "\n")
            raise errors.AnsibleError("failed to parse executable inventory script results: %s" % self.raw)

        for (group_name, data) in self.raw.items():
 
            # in Ansible 1.3 and later, a "_meta" subelement may contain
            # a variable "hostvars" which contains a hash for each host
            # if this "hostvars" exists at all then do not call --host for each
            # host.  This is for efficiency and scripts should still return data
            # if called with --host for backwards compat with 1.2 and earlier.

            if group_name == '_meta':
                if 'hostvars' in data:
                    self.host_vars_from_top = data['hostvars']
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,7 +49,7 @@
     def _parse(self, err):
 
         all_hosts = {}
-        self.raw  = utils.parse_json(self.data)
+        self.raw  = utils.parse_json(self.data, from_remote=True)
         all       = Group('all')
         groups    = dict(all=all)
         group     = None
```
