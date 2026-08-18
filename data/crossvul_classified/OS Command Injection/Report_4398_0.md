# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in go
**Pair ID:** 4398_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4398_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```go
Lines 4-44 of the vulnerable file.

	"bytes"
	"fmt"
	"text/template"

	types "github.com/go-vela/types/yaml"

	"github.com/Masterminds/sprig"

	yaml "gopkg.in/yaml.v2"
)

// Render combines the template with the step in the yaml pipeline.
func Render(tmpl string, s *types.Step) (types.StepSlice, error) {
	buffer := new(bytes.Buffer)
	config := new(types.Build)

	velaFuncs := funcHandler{envs: convertPlatformVars(s.Environment)}
	templateFuncMap := map[string]interface{}{
		"vela": velaFuncs.returnPlatformVar,
	}

	// parse the template with Masterminds/sprig functions
	//
	// https://pkg.go.dev/github.com/Masterminds/sprig?tab=doc#TxtFuncMap
	t, err := template.New(s.Name).Funcs(sprig.TxtFuncMap()).Funcs(templateFuncMap).Parse(tmpl)
	if err != nil {
		return types.StepSlice{}, fmt.Errorf("unable to parse template %s: %v", s.Template.Name, err)
	}

	// apply the variables to the parsed template
	err = t.Execute(buffer, s.Template.Variables)
	if err != nil {
		return types.StepSlice{}, fmt.Errorf("unable to execute template %s: %v", s.Template.Name, err)
	}

	// unmarshal the template to the pipeline
	err = yaml.Unmarshal(buffer.Bytes(), config)
	if err != nil {
		return types.StepSlice{}, fmt.Errorf("unable to unmarshal yaml: %v", err)
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,11 +21,18 @@
 	templateFuncMap := map[string]interface{}{
 		"vela": velaFuncs.returnPlatformVar,
 	}
+	// modify Masterminds/sprig functions
+	// to remove OS functions
+	//
+	// https://masterminds.github.io/sprig/os.html
+	sf := sprig.TxtFuncMap()
+	delete(sf, "env")
+	delete(sf, "expandenv")
 
 	// parse the template with Masterminds/sprig functions
 	//
 	// https://pkg.go.dev/github.com/Masterminds/sprig?tab=doc#TxtFuncMap
-	t, err := template.New(s.Name).Funcs(sprig.TxtFuncMap()).Funcs(templateFuncMap).Parse(tmpl)
+	t, err := template.New(s.Name).Funcs(sf).Funcs(templateFuncMap).Parse(tmpl)
 	if err != nil {
 		return types.StepSlice{}, fmt.Errorf("unable to parse template %s: %v", s.Template.Name, err)
 	}
```
