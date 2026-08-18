# CrossVul Fix Pair: Cryptographic Issues in ruby
**Pair ID:** 2032_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2032_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```ruby
Lines 502-542 of the vulnerable file.

          path_parts = $'.sub(/#.*/, '').split('/')
          gist_id = path_parts.last
          patch_name = "gist-#{gist_id}.txt"
          patch = api_client.gist_raw(gist_id)
        else
          gh_url = resolve_github_url(url)
          case gh_url.project_path
          when /^pull\/(\d+)/
            pull_id = $1.to_i
            patch_name = "#{pull_id}.patch"
            patch = api_client.pullrequest_patch(gh_url.project, pull_id)
          when /^commit\/([a-f0-9]{7,40})/
            commit_sha = $1
            patch_name = "#{commit_sha}.patch"
            patch = api_client.commit_patch(gh_url.project, commit_sha)
          else
            raise ArgumentError, url
          end
        end

        patch_file = File.join(tmp_dir, patch_name)
        File.open(patch_file, 'w') { |file| file.write(patch) }
        args[idx] = patch_file
      end
    end

    # $ hub apply https://github.com/defunkt/hub/pull/55
    # ... downloads patch via API ...
    # > git apply /tmp/55.patch
    alias_method :apply, :am

    # $ hub init -g
    # > git init
    # > git remote add origin git@github.com:USER/REPO.git
    def init(args)
      if args.delete('-g')
        project = github_project(File.basename(current_dir))
        url = project.git_url(:private => true, :https => https_protocol?)
        args.after ['remote', 'add', 'origin', url]
      end
    end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -519,7 +519,7 @@
           end
         end
 
-        patch_file = File.join(tmp_dir, patch_name)
+        patch_file = Tempfile.new('patch_name')
         File.open(patch_file, 'w') { |file| file.write(patch) }
         args[idx] = patch_file
       end
```
