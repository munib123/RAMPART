# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 1728_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1728_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 142-182 of the vulnerable file.

            session_manager, kernel_spec_manager, config_manager, log, base_url,
            default_url, settings_overrides, jinja_env_options)
        handlers = self.init_handlers(settings)

        super(NotebookWebApplication, self).__init__(handlers, **settings)

    def init_settings(self, ipython_app, kernel_manager, contents_manager,
                      session_manager, kernel_spec_manager,
                      config_manager,
                      log, base_url, default_url, settings_overrides,
                      jinja_env_options=None):

        _template_path = settings_overrides.get(
            "template_path",
            ipython_app.template_file_path,
        )
        if isinstance(_template_path, py3compat.string_types):
            _template_path = (_template_path,)
        template_path = [os.path.expanduser(path) for path in _template_path]

        jenv_opt = jinja_env_options if jinja_env_options else {}
        env = Environment(loader=FileSystemLoader(template_path), **jenv_opt)
        
        sys_info = get_sys_info()
        if sys_info['commit_source'] == 'repository':
            # don't cache (rely on 304) when working from master
            version_hash = ''
        else:
            # reset the cache on server restart
            version_hash = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

        settings = dict(
            # basics
            log_function=log_request,
            base_url=base_url,
            default_url=default_url,
            template_path=template_path,
            static_path=ipython_app.static_file_path,
            static_custom_path=ipython_app.static_custom_path,
            static_handler_class = FileFindHandler,
            static_url_prefix = url_path_join(base_url,'/static/'),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -159,7 +159,9 @@
             _template_path = (_template_path,)
         template_path = [os.path.expanduser(path) for path in _template_path]
 
-        jenv_opt = jinja_env_options if jinja_env_options else {}
+        jenv_opt = {"autoescape": True}
+        jenv_opt.update(jinja_env_options if jinja_env_options else {})
+
         env = Environment(loader=FileSystemLoader(template_path), **jenv_opt)
         
         sys_info = get_sys_info()
```
