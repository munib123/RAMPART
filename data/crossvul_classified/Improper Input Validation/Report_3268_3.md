# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 3268_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3268_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 234-274 of the vulnerable file.

            self._test_loader   = getattr(shared_loader_obj, 'test_loader')
            self._lookup_loader = getattr(shared_loader_obj, 'lookup_loader')
        else:
            self._filter_loader = filter_loader
            self._test_loader   = test_loader
            self._lookup_loader = lookup_loader

        # flags to determine whether certain failures during templating
        # should result in fatal errors being raised
        self._fail_on_lookup_errors    = True
        self._fail_on_filter_errors    = True
        self._fail_on_undefined_errors = C.DEFAULT_UNDEFINED_VAR_BEHAVIOR

        self.environment = AnsibleEnvironment(
            trim_blocks=True,
            undefined=StrictUndefined,
            extensions=self._get_extensions(),
            finalize=self._finalize,
            loader=FileSystemLoader(self._basedir),
        )

        self.SINGLE_VAR = re.compile(r"^%s\s*(\w*)\s*%s$" % (self.environment.variable_start_string, self.environment.variable_end_string))

        self._clean_regex   = re.compile(r'(?:%s|%s|%s|%s)' % (
            self.environment.variable_start_string,
            self.environment.block_start_string,
            self.environment.block_end_string,
            self.environment.variable_end_string
        ))
        self._no_type_regex = re.compile(r'.*\|\s*(?:%s)\s*(?:%s)?$' % ('|'.join(C.STRING_TYPE_FILTERS), self.environment.variable_end_string))

    def _get_filters(self):
        '''
        Returns filter plugins, after loading and caching them if need be
        '''

        if self._filters is not None:
            return self._filters.copy()

        plugins = [x for x in self._filter_loader.all()]

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -251,6 +251,9 @@
             finalize=self._finalize,
             loader=FileSystemLoader(self._basedir),
         )
+
+        # the current rendering context under which the templar class is working
+        self.cur_context = None
 
         self.SINGLE_VAR = re.compile(r"^%s\s*(\w*)\s*%s$" % (self.environment.variable_start_string, self.environment.variable_end_string))
 
@@ -574,6 +577,7 @@
 
         if instance is not None:
             wantlist = kwargs.pop('wantlist', False)
+            allow_unsafe = kwargs.pop('allow_unsafe', C.DEFAULT_ALLOW_UNSAFE_LOOKUPS)
 
             from ansible.utils.listify import listify_lookup_plugin_terms
             loop_terms = listify_lookup_plugin_terms(terms=args, templar=self, loader=self._loader, fail_on_undefined=True, convert_bare=False)
@@ -588,7 +592,8 @@
                                        "original message: %s" % (name, type(e), e))
                 ran = None
 
-            if ran:
+            if ran and not allow_unsafe:
+                from ansible.vars.unsafe_proxy import UnsafeProxy, wrap_var
                 if wantlist:
                     ran = wrap_var(ran)
                 else:
@@ -600,6 +605,8 @@
                         else:
                             ran = wrap_var(ran)
 
+                if self.cur_context:
+                    self.cur_context.unsafe = True
             return ran
         else:
             raise AnsibleError("lookup plugin (%s) not found" % name)
@@ -656,7 +663,7 @@
 
             jvars = AnsibleJ2Vars(self, t.globals)
 
-            new_context = t.new_context(jvars, shared=True)
+            self.cur_context = new_context = t.new_context(jvars, shared=True)
             rf = t.root_render_func(new_context)
 
             try:
```
