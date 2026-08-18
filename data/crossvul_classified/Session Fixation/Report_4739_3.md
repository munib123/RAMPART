# CrossVul Fix Pair: Session Fixation in ruby
**Pair ID:** 4739_3
**Vulnerability Class:** Session Fixation
**CWE:** CWE-384
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4739_3`)

## Vulnerability Information & PoC

## Description
Session Fixation - Such a scenario is commonly observed when: A web application authenticates a user without first invalidating the existing session, thereby continuing to use the session already associated with the ...

## Vulnerable Code
```ruby
Lines 1-21 of the vulnerable file.

def getFenceAgents(session, fence_agent = nil)
  fence_agent_list = {}
  agents = Dir.glob('/usr/sbin/fence_' + '*')
  agents.each { |a|
    fa = FenceAgent.new
    fa.name =  a.sub(/.*\//,"")
    next if fa.name == "fence_ack_manual"

    if fence_agent and a.sub(/.*\//,"") == fence_agent.sub(/.*:/,"")
      required_options, optional_options, advanced_options, info = getFenceAgentMetadata(session, fa.name)
      fa.required_options = required_options
      fa.optional_options = optional_options
      fa.advanced_options = advanced_options
      fa.info = info
    end
    fence_agent_list[fa.name] = fa
  }
  fence_agent_list
end

def getFenceAgentMetadata(session, fenceagentname)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-def getFenceAgents(session, fence_agent = nil)
+def getFenceAgents(auth_user, fence_agent = nil)
   fence_agent_list = {}
   agents = Dir.glob('/usr/sbin/fence_' + '*')
   agents.each { |a|
@@ -7,7 +7,7 @@
     next if fa.name == "fence_ack_manual"
 
     if fence_agent and a.sub(/.*\//,"") == fence_agent.sub(/.*:/,"")
-      required_options, optional_options, advanced_options, info = getFenceAgentMetadata(session, fa.name)
+      required_options, optional_options, advanced_options, info = getFenceAgentMetadata(auth_user, fa.name)
       fa.required_options = required_options
       fa.optional_options = optional_options
       fa.advanced_options = advanced_options
@@ -18,7 +18,7 @@
   fence_agent_list
 end
 
-def getFenceAgentMetadata(session, fenceagentname)
+def getFenceAgentMetadata(auth_user, fenceagentname)
   options_required = {}
   options_optional = {}
   options_advanced = {
@@ -43,7 +43,7 @@
     return [options_required, options_optional, options_advanced]
   end
   stdout, stderr, retval = run_cmd(
-    session, "/usr/sbin/#{fenceagentname}", '-o', 'metadata'
+    auth_user, "/usr/sbin/#{fenceagentname}", '-o', 'metadata'
   )
   metadata = stdout.join
   begin
```
