# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 783_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `783_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 173-213 of the vulnerable file.

Git.prototype.checkout = function(repo, cb) {
	var self = this;
	var dir = this.checkoutDir(repo.organization, repo.name);
	mkdirp(dir, init);

	function init(err) {
		if (err)
			return cb('mkdirp(' + dir + ') failed');
		debug('mkdirp() ' + dir + ' finished');
		child.exec('git init', {
			cwd : dir
		}, function(err, stdo, stde) {
			if (err)
				return cb(err);
			debug('init() ' + dir + ' finished');
			fetch();
		});
	}

	function fetch() {
		var cmd = ['git', 'fetch', 'file://' + path.resolve(self.repoDir, repo.organization, repo.name), repo.branch].join(' ');

		child.exec(cmd, {
			cwd : dir
		}, function(err) {
			if (err)
				return cb(err);
			debug('fetch() ' + dir + ' finished');
			checkout();
		});
	}

	function checkout() {
		var cmd = ['git', 'checkout', '-b', repo.branch, repo.commit].join(' ');

		child.exec(cmd, {
			cwd : dir
		}, function(err, stdo, stde) {
			cb(err, stdo, stde);
		});
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -190,7 +190,7 @@
 	}
 
 	function fetch() {
-		var cmd = ['git', 'fetch', 'file://' + path.resolve(self.repoDir, repo.organization, repo.name), repo.branch].join(' ');
+		var cmd = ['git', 'fetch', 'file://' + path.resolve(self.repoDir, repo.organization, repo.name), encodeURIComponent(repo.branch)].join(' ');
 
 		child.exec(cmd, {
 			cwd : dir
@@ -203,7 +203,7 @@
 	}
 
 	function checkout() {
-		var cmd = ['git', 'checkout', '-b', repo.branch, repo.commit].join(' ');
+		var cmd = ['git', 'checkout', '-b', encodeURIComponent(repo.branch), repo.commit].join(' ');
 
 		child.exec(cmd, {
 			cwd : dir
@@ -218,7 +218,7 @@
 	var self = this;
 	var dir = this.checkoutDir(repo.organization, repo.name);
 	repo.id = repo.commit + '.' + Date.now();
-	var cmd = ['git', 'pull', 'file://' + path.resolve(self.repoDir, repo.organization, repo.name), repo.branch].join(' ');
+	var cmd = ['git', 'pull', 'file://' + path.resolve(self.repoDir, repo.organization, repo.name), encodeURIComponent(repo.branch)].join(' ');
 	debug('Git.pull ' + dir + ': ' + cmd);
 	child.exec(cmd, {
 		cwd : dir
```
