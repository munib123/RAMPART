# CrossVul Fix Pair: Session Fixation in ruby
**Pair ID:** 4739_1
**Vulnerability Class:** Session Fixation
**CWE:** CWE-384
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4739_1`)

## Vulnerability Information & PoC

## Description
Session Fixation - Such a scenario is commonly observed when: A web application authenticates a user without first invalidating the existing session, thereby continuing to use the session already associated with the ...

## Vulnerable Code
```ruby
Lines 408-448 of the vulnerable file.

      begin
        file = nil
        file = File.open(CFG_SYNC_CONTROL, 'w', 0600)
        file.flock(File::LOCK_EX)
        file.write(text)
      rescue => e
        $logger.error("Cannot save config '#{CFG_SYNC_CONTROL}': #{e.message}")
        return false
      ensure
        unless file.nil?
          file.flock(File::LOCK_UN)
          file.close()
        end
      end
      return true
    end
  end


  class ConfigPublisher
    def initialize(session, configs, nodes, cluster_name, tokens={})
      @configs = configs
      @nodes = nodes
      @cluster_name = cluster_name
      @published_configs_names = @configs.collect { |cfg|
        cfg.class.name
      }
      @additional_tokens = tokens
      @session = session
    end

    def send(force=false)
      nodes_txt = @nodes.join(', ')
      @configs.each { |cfg|
        $logger.info(
          "Sending config '#{cfg.class.name}' version #{cfg.version} #{cfg.hash}"\
          + " to nodes: #{nodes_txt}"
        )
      }

      data = self.prepare_request_data(@configs, @cluster_name, force)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -425,7 +425,7 @@
 
 
   class ConfigPublisher
-    def initialize(session, configs, nodes, cluster_name, tokens={})
+    def initialize(auth_user, configs, nodes, cluster_name, tokens={})
       @configs = configs
       @nodes = nodes
       @cluster_name = cluster_name
@@ -433,7 +433,7 @@
         cfg.class.name
       }
       @additional_tokens = tokens
-      @session = session
+      @auth_user = auth_user
     end
 
     def send(force=false)
@@ -451,7 +451,7 @@
       @nodes.each { |node|
         threads << Thread.new {
           code, out = send_request_with_token(
-            @session, node, 'set_configs', true, data, true, nil, 30,
+            @auth_user, node, 'set_configs', true, data, true, nil, 30,
             @additional_tokens
           )
           if 200 == code
@@ -535,11 +535,11 @@
 
 
   class ConfigFetcher
-    def initialize(session, config_classes, nodes, cluster_name)
+    def initialize(auth_user, config_classes, nodes, cluster_name)
       @config_classes = config_classes
       @nodes = nodes
       @cluster_name = cluster_name
-      @session = session
+      @auth_user = auth_user
     end
 
     def fetch_all()
@@ -591,7 +591,7 @@
       nodes.each { |node|
         threads << Thread.new {
           code, out = send_request_with_token(
-            @session, node, 'get_configs', false, data
+            @auth_user, node, 'get_configs', false, data
           )
           if 200 == code
             begin
@@ -700,13 +700,13 @@
     else
       # we run in a cluster so we need to sync the config
       publisher = ConfigPublisher.new(
-        PCSAuth.getSuperuserSession(), [config], nodes, cluster_name, tokens
+        PCSAuth.getSuperuserAuth(), [config], nodes, cluster_name, tokens
       )
       old_configs, node_responses = publisher.publish()
       if old_configs.include?(config.class.name)
         if fetch_on_conflict
           fetcher = ConfigFetcher.new(
-            PCSAuth.getSuperuserSession(), [config.class], nodes, cluster_name
+            PCSAuth.getSuperuserAuth(), [config.class], nodes, cluster_name
           )
           cfgs_to_save, _ = fetcher.fetch()
           cfgs_to_save.each { |cfg_to_save|
@@ -751,7 +751,7 @@
     end
     # we run in a cluster so we need to sync the config
     publisher = ConfigPublisher.new(
-      PCSAuth.getSuperuserSession(), [config_new], nodes, cluster_name,
+      PCSAuth.getSuperuserAuth(), [config_new], nodes, cluster_name,
       new_tokens
     )
     old_configs, node_responses = publisher.publish()
@@ -761,7 +761,7 @@
     end
     # get tokens from all nodes and merge them
     fetcher = ConfigFetcher.new(
-      PCSAuth.getSuperuserSession(), [config_new.class], nodes, cluster_name
+      PCSAuth.getSuperuserAuth(), [config_new.class], nodes, cluster_name
     )
     fetched_tokens = fetcher.fetch_all()[config_new.class.name]
     config_new = Cfgsync::merge_tokens_files(config, fetched_tokens, new_tokens)
```
