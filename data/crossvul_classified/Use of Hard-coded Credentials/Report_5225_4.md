# CrossVul Fix Pair: Use of Hard-coded Credentials in ruby
**Pair ID:** 5225_4
**Vulnerability Class:** Use of Hard-coded Credentials
**CWE:** CWE-798
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5225_4`)

## Vulnerability Information & PoC

## Description
Use of Hard-coded Credentials - Hard-coded credentials typically create a significant hole that allows an attacker to bypass the authentication that has been configured by the product administrator.

## Vulnerable Code
```ruby
Lines 28-68 of the vulnerable file.

          "count" => 1,
          "exclude_platform" => {
            "suse" => "12.0",
            "windows" => "/.*/"
          }
        }
      }
    end
  end

  def create_proposal
    @logger.debug("Trove create_proposal: entering")
    base = super

    base["attributes"][@bc_name]["keystone_instance"] = find_dep_proposal("keystone")
    base["attributes"][@bc_name]["nova_instance"] = find_dep_proposal("nova")
    base["attributes"][@bc_name]["cinder_instance"] = find_dep_proposal("cinder")
    base["attributes"][@bc_name]["swift_instance"] = find_dep_proposal("swift", true)
    base["attributes"][@bc_name]["rabbitmq_instance"] = find_dep_proposal("rabbitmq")
    base["attributes"][@bc_name]["db"]["password"] = random_password

    # assign a default node to the trove-server role
    nodes = NodeObject.all
    nodes.delete_if { |n| n.nil? or n.admin? }
    if nodes.size >= 1
      controller = nodes.find { |n| n.intended_role == "controller" } || nodes.first
      base["deployment"]["trove"]["elements"] = {
        "trove-server" => [ controller[:fqdn] ]
      }
    end

    @logger.debug("Trove create_proposal: exiting")
    base
  end

  def proposal_dependencies(role)
    answer = []
    answer << { "barclamp" => "keystone", "inst" => role.default_attributes[@bc_name]["keystone_instance"] }
    answer << { "barclamp" => "nova", "inst" => role.default_attributes[@bc_name]["nova_instance"] }
    answer << { "barclamp" => "cinder", "inst" => role.default_attributes[@bc_name]["cinder_instance"] }
    answer << { "barclamp" => "rabbitmq", "inst" => role.default_attributes[@bc_name]["rabbitmq_instance"] }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,6 +45,7 @@
     base["attributes"][@bc_name]["swift_instance"] = find_dep_proposal("swift", true)
     base["attributes"][@bc_name]["rabbitmq_instance"] = find_dep_proposal("rabbitmq")
     base["attributes"][@bc_name]["db"]["password"] = random_password
+    base["attributes"][@bc_name]["service_password"] = random_password
 
     # assign a default node to the trove-server role
     nodes = NodeObject.all
```
