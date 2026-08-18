# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 3560_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3560_3`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 118-158 of the vulnerable file.

    num_tries += 1
  end

  cdb.create_id_map
  Chef::Node.create_design_document
  Chef::Role.create_design_document
  Chef::DataBag.create_design_document
  Chef::ApiClient.create_design_document
  Chef::WebUIUser.create_design_document
  Chef::CookbookVersion.create_design_document
  Chef::Sandbox.create_design_document
  Chef::Checksum.create_design_document
  Chef::Environment.create_design_document

  Chef::Certificate.generate_signing_ca
  Chef::Certificate.gen_validation_key
  Chef::Certificate.gen_validation_key(Chef::Config[:web_ui_client_name], Chef::Config[:web_ui_key])
  Chef::Environment.create_default_environment
  system("cp #{File.join(Dir.tmpdir, "chef_integration", "validation.pem")} #{Dir.tmpdir}")
  system("cp #{File.join(Dir.tmpdir, "chef_integration", "webui.pem")} #{Dir.tmpdir}")

  cmd = [KNIFE_CMD, "cookbook", "upload", "-a", "-o", INTEGRATION_COOKBOOKS, "-u", "validator", "-k", File.join(Dir.tmpdir, "validation.pem"), "-c", KNIFE_CONFIG]
  Chef::Log.info("Uploading fixture cookbooks with #{cmd.join(' ')}")
  cmd << {:timeout => 120}
  shell_out!(*cmd)
end

def prepare_replicas
  replicate_dbs({ :source_db => "#{Chef::Config[:couchdb_url]}/chef_integration", :target_db => "#{Chef::Config[:couchdb_url]}/chef_integration_safe" })
end

def cleanup
  if File.exists?(Chef::Config[:validation_key])
    File.unlink(Chef::Config[:validation_key])
  end
  if File.exists?(Chef::Config[:web_ui_key])
    File.unlink(Chef::Config[:web_ui_key])
  end
end

###
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -135,8 +135,11 @@
   Chef::Environment.create_default_environment
   system("cp #{File.join(Dir.tmpdir, "chef_integration", "validation.pem")} #{Dir.tmpdir}")
   system("cp #{File.join(Dir.tmpdir, "chef_integration", "webui.pem")} #{Dir.tmpdir}")
-
-  cmd = [KNIFE_CMD, "cookbook", "upload", "-a", "-o", INTEGRATION_COOKBOOKS, "-u", "validator", "-k", File.join(Dir.tmpdir, "validation.pem"), "-c", KNIFE_CONFIG]
+  c = Chef::ApiClient.cdb_load(Chef::Config[:web_ui_client_name])
+  c.admin(true)
+  c.cdb_save
+
+  cmd = [KNIFE_CMD, "cookbook", "upload", "-a", "-o", INTEGRATION_COOKBOOKS, "-u", Chef::Config[:web_ui_client_name], "-k", File.join(Dir.tmpdir, "webui.pem"), "-c", KNIFE_CONFIG]
   Chef::Log.info("Uploading fixture cookbooks with #{cmd.join(' ')}")
   cmd << {:timeout => 120}
   shell_out!(*cmd)
```
