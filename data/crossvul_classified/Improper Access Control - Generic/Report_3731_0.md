# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 3731_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3731_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 582-622 of the vulnerable file.

          raise "Cannot specify both the node_name_value and node_name_fact settings"
        end
      end
    },
    :localconfig => { :default => "$statedir/localconfig",
      :owner => "root",
      :mode => 0660,
      :desc => "Where puppet agent caches the local configuration.  An
        extension indicating the cache format is added automatically."},
    :statefile => { :default => "$statedir/state.yaml",
      :mode => 0660,
      :desc => "Where puppet agent and puppet master store state associated
        with the running configuration.  In the case of puppet master,
        this file reflects the state discovered through interacting
        with clients."
      },
    :clientyamldir => {:default => "$vardir/client_yaml", :mode => "750", :desc => "The directory in which client-side YAML data is stored."},
    :client_datadir => {:default => "$vardir/client_data", :mode => "750", :desc => "The directory in which serialized data is stored on the client."},
    :classfile => { :default => "$statedir/classes.txt",
      :owner => "root",
      :mode => 0644,
      :desc => "The file in which puppet agent stores a list of the classes
        associated with the retrieved configuration.  Can be loaded in
        the separate `puppet` executable using the `--loadclasses`
        option."},
    :resourcefile => { :default => "$statedir/resources.txt",
      :owner => "root",
      :mode => 0644,
      :desc => "The file in which puppet agent stores a list of the resources
        associated with the retrieved configuration."  },
    :puppetdlog => { :default => "$logdir/puppetd.log",
      :owner => "root",
      :mode => 0640,
      :desc => "The log file for puppet agent.  This is generally not used."
    },
    :server => ["puppet", "The server to which server puppet agent should connect"],
    :ignoreschedules => [false,
      "Boolean; whether puppet agent should ignore schedules.  This is useful
      for initial puppet agent runs."],
    :puppetport => [8139, "Which port puppet agent listens on."],
    :noop => [false, "Whether puppet agent should be run in noop mode."],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -599,14 +599,14 @@
     :client_datadir => {:default => "$vardir/client_data", :mode => "750", :desc => "The directory in which serialized data is stored on the client."},
     :classfile => { :default => "$statedir/classes.txt",
       :owner => "root",
-      :mode => 0644,
+      :mode => 0640,
       :desc => "The file in which puppet agent stores a list of the classes
         associated with the retrieved configuration.  Can be loaded in
         the separate `puppet` executable using the `--loadclasses`
         option."},
     :resourcefile => { :default => "$statedir/resources.txt",
       :owner => "root",
-      :mode => 0644,
+      :mode => 0640,
       :desc => "The file in which puppet agent stores a list of the resources
         associated with the retrieved configuration."  },
     :puppetdlog => { :default => "$logdir/puppetd.log",
@@ -713,11 +713,11 @@
       "Whether to send reports after every transaction."
     ],
     :lastrunfile =>  { :default => "$statedir/last_run_summary.yaml",
-      :mode => 0644,
+      :mode => 0640,
       :desc => "Where puppet agent stores the last run report summary in yaml format."
     },
     :lastrunreport =>  { :default => "$statedir/last_run_report.yaml",
-      :mode => 0644,
+      :mode => 0640,
       :desc => "Where puppet agent stores the last run report in yaml format."
     },
     :graph => [false, "Whether to create dot graph files for the different
```
