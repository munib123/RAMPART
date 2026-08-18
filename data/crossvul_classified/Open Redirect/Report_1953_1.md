# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 1953_1
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1953_1`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 91-125 of the vulnerable file.

            if "?" in request.raw_path:
                path, query = request.raw_path.split("?", 1)
                query = "?" + query
            else:
                query = ""
                path = request.raw_path

            if merge_slashes:
                paths_to_check.append(re.sub("//+", "/", path))
            if append_slash and not request.path.endswith("/"):
                paths_to_check.append(path + "/")
            if remove_slash and request.path.endswith("/"):
                paths_to_check.append(path[:-1])
            if merge_slashes and append_slash:
                paths_to_check.append(re.sub("//+", "/", path + "/"))
            if merge_slashes and remove_slash and path.endswith("/"):
                merged_slashes = re.sub("//+", "/", path)
                paths_to_check.append(merged_slashes[:-1])

            for path in paths_to_check:
                resolves, request = await _check_request_resolves(request, path)
                if resolves:
                    raise redirect_class(request.raw_path + query)

        return await handler(request)

    return impl


def _fix_request_current_app(app: "Application") -> _Middleware:
    async def impl(request: Request, handler: _Handler) -> StreamResponse:
        with request.match_info.set_current_app(app):
            return await handler(request)

    return impl
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -108,6 +108,7 @@
                 paths_to_check.append(merged_slashes[:-1])
 
             for path in paths_to_check:
+                path = re.sub("^//+", "/", path)  # SECURITY: GHSA-v6wp-4m6f-gcjg
                 resolves, request = await _check_request_resolves(request, path)
                 if resolves:
                     raise redirect_class(request.raw_path + query)
```
