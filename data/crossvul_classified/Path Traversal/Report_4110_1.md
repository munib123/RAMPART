# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in python
**Pair ID:** 4110_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4110_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```python
Lines 66-106 of the vulnerable file.

    yaml_bytes: bytes
    if url is not None and path is not None:
        return GeneratorError(header="Provide URL or Path, not both.")
    if url is not None:
        try:
            response = httpx.get(url)
            yaml_bytes = response.content
        except (httpx.HTTPError, httpcore.NetworkError):
            return GeneratorError(header="Could not get OpenAPI document from provided URL")
    elif path is not None:
        yaml_bytes = path.read_bytes()
    else:
        return GeneratorError(header="No URL or Path provided")
    try:
        return yaml.safe_load(yaml_bytes)
    except yaml.YAMLError:
        return GeneratorError(header="Invalid YAML from provided source")


class Project:
    TEMPLATE_FILTERS = {"snakecase": utils.snake_case, "spinalcase": utils.spinal_case}
    project_name_override: Optional[str] = None
    package_name_override: Optional[str] = None

    def __init__(self, *, openapi: GeneratorData) -> None:
        self.openapi: GeneratorData = openapi
        self.env: Environment = Environment(loader=PackageLoader(__package__), trim_blocks=True, lstrip_blocks=True)

        self.project_name: str = self.project_name_override or f"{openapi.title.replace(' ', '-').lower()}-client"
        self.project_dir: Path = Path.cwd() / self.project_name

        self.package_name: str = self.package_name_override or self.project_name.replace("-", "_")
        self.package_dir: Path = self.project_dir / self.package_name
        self.package_description: str = f"A client library for accessing {self.openapi.title}"
        self.version: str = openapi.version

        self.env.filters.update(self.TEMPLATE_FILTERS)

    def build(self) -> Sequence[GeneratorError]:
        """ Create the project from templates """

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -83,7 +83,7 @@
 
 
 class Project:
-    TEMPLATE_FILTERS = {"snakecase": utils.snake_case, "spinalcase": utils.spinal_case}
+    TEMPLATE_FILTERS = {"snakecase": utils.snake_case, "kebabcase": utils.kebab_case}
     project_name_override: Optional[str] = None
     package_name_override: Optional[str] = None
 
@@ -91,7 +91,7 @@
         self.openapi: GeneratorData = openapi
         self.env: Environment = Environment(loader=PackageLoader(__package__), trim_blocks=True, lstrip_blocks=True)
 
-        self.project_name: str = self.project_name_override or f"{openapi.title.replace(' ', '-').lower()}-client"
+        self.project_name: str = self.project_name_override or f"{utils.kebab_case(openapi.title).lower()}-client"
         self.project_dir: Path = Path.cwd() / self.project_name
 
         self.package_name: str = self.package_name_override or self.project_name.replace("-", "_")
@@ -231,6 +231,7 @@
         endpoint_template = self.env.get_template("endpoint_module.pyi")
         async_endpoint_template = self.env.get_template("async_endpoint_module.pyi")
         for tag, collection in self.openapi.endpoint_collections_by_tag.items():
+            tag = utils.snake_case(tag)
             module_path = api_dir / f"{tag}.py"
             module_path.write_text(endpoint_template.render(collection=collection))
             async_module_path = async_api_dir / f"{tag}.py"
```
