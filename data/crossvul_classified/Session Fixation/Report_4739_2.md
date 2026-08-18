# CrossVul Fix Pair: Session Fixation in ruby
**Pair ID:** 4739_2
**Vulnerability Class:** Session Fixation
**CWE:** CWE-384
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4739_2`)

## Vulnerability Information & PoC

## Description
Session Fixation - Such a scenario is commonly observed when: A web application authenticates a user without first invalidating the existing session, thereby continuing to use the session already associated with the ...

## Vulnerable Code
```ruby
Lines 1001-1041 of the vulnerable file.

    attr_accessor :id, :error_list, :warning_list, :status, :quorum, :uptime,
                  :name, :corosync, :pacemaker, :cman, :corosync_enabled,
                  :pacemaker_enabled, :pcsd_enabled

    def initialize
      @id = nil
      @error_list = []
      @warning_list = []
      @status = 'unknown'
      @quorum = nil
      @uptime = 'unknown'
      @name = nil
      @corosync = false
      @pacemaker = false
      @cman = false
      @corosync_enabled = false
      @pacemaker_enabled = false
      @pcsd_enabled = false
    end

    def self.load_current_node(session, crm_dom=nil)
      node = ClusterEntity::Node.new
      node.corosync = corosync_running?
      node.corosync_enabled = corosync_enabled?
      node.pacemaker = pacemaker_running?
      node.pacemaker_enabled = pacemaker_enabled?
      node.cman = cman_running?
      node.pcsd_enabled = pcsd_enabled?

      node_online = (node.corosync and node.pacemaker)
      node.status =  node_online ? 'online' : 'offline'

      node.uptime = get_node_uptime
      node.id = get_local_node_id

      if node_online and crm_dom
        node_el = crm_dom.elements["//node[@id='#{node.id}']"]
        if node_el and node_el.attributes['standby'] == 'true'
          node.status = 'standby'
        else
          node.status = 'online'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1018,7 +1018,7 @@
       @pcsd_enabled = false
     end
 
-    def self.load_current_node(session, crm_dom=nil)
+    def self.load_current_node(crm_dom=nil)
       node = ClusterEntity::Node.new
       node.corosync = corosync_running?
       node.corosync_enabled = corosync_enabled?
```
