# CrossVul Fix Pair: Improper Input Validation in go
**Pair ID:** 4139_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4139_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```go
Lines 64-94 of the vulnerable file.

	Type string `json:"type,omitempty"`
}

// Validate checks the metadata for known issues, returning an error if metadata is not correct
func (md *Metadata) Validate() error {
	if md == nil {
		return ValidationError("chart.metadata is required")
	}
	if md.APIVersion == "" {
		return ValidationError("chart.metadata.apiVersion is required")
	}
	if md.Name == "" {
		return ValidationError("chart.metadata.name is required")
	}
	if md.Version == "" {
		return ValidationError("chart.metadata.version is required")
	}
	if !isValidChartType(md.Type) {
		return ValidationError("chart.metadata.type must be application or library")
	}
	// TODO validate valid semver here?
	return nil
}

func isValidChartType(in string) bool {
	switch in {
	case "", "application", "library":
		return true
	}
	return false
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -81,6 +81,15 @@
 	if !isValidChartType(md.Type) {
 		return ValidationError("chart.metadata.type must be application or library")
 	}
+
+	// Aliases need to be validated here to make sure that the alias name does
+	// not contain any illegal characters.
+	for _, dependency := range md.Dependencies {
+		if err := validateDependency(dependency); err != nil {
+			return err
+		}
+	}
+
 	// TODO validate valid semver here?
 	return nil
 }
@@ -92,3 +101,13 @@
 	}
 	return false
 }
+
+// validateDependency checks for common problems with the dependency datastructure in
+// the chart. This check must be done at load time before the dependency's charts are
+// loaded.
+func validateDependency(dep *Dependency) error {
+	if len(dep.Alias) > 0 && !aliasNameFormat.MatchString(dep.Alias) {
+		return ValidationErrorf("dependency %q has disallowed characters in the alias", dep.Name)
+	}
+	return nil
+}
```
