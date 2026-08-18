# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in go
**Pair ID:** 1937_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1937_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```go
Lines 46-86 of the vulnerable file.

	o := &repoUpdateOptions{update: updateCharts}

	cmd := &cobra.Command{
		Use:               "update",
		Aliases:           []string{"up"},
		Short:             "update information of available charts locally from chart repositories",
		Long:              updateDesc,
		Args:              require.NoArgs,
		ValidArgsFunction: noCompletions,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.repoFile = settings.RepositoryConfig
			o.repoCache = settings.RepositoryCache
			return o.run(out)
		},
	}
	return cmd
}

func (o *repoUpdateOptions) run(out io.Writer) error {
	f, err := repo.LoadFile(o.repoFile)
	if isNotExist(err) || len(f.Repositories) == 0 {
		return errNoRepositories
	}
	var repos []*repo.ChartRepository
	for _, cfg := range f.Repositories {
		r, err := repo.NewChartRepository(cfg, getter.All(settings))
		if err != nil {
			return err
		}
		if o.repoCache != "" {
			r.CachePath = o.repoCache
		}
		repos = append(repos, r)
	}

	o.update(repos, out)
	return nil
}

func updateCharts(repos []*repo.ChartRepository, out io.Writer) {
	fmt.Fprintln(out, "Hang tight while we grab the latest from your chart repositories...")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,9 +63,15 @@
 
 func (o *repoUpdateOptions) run(out io.Writer) error {
 	f, err := repo.LoadFile(o.repoFile)
-	if isNotExist(err) || len(f.Repositories) == 0 {
+	switch {
+	case isNotExist(err):
+		return errNoRepositories
+	case err != nil:
+		return errors.Wrapf(err, "failed loading file: %s", o.repoFile)
+	case len(f.Repositories) == 0:
 		return errNoRepositories
 	}
+
 	var repos []*repo.ChartRepository
 	for _, cfg := range f.Repositories {
 		r, err := repo.NewChartRepository(cfg, getter.All(settings))
```
