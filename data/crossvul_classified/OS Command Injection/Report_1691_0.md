# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in ruby
**Pair ID:** 1691_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1691_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```ruby
Lines 1-36 of the vulnerable file.

require 'json'

module Isucon5Portal::GCloud
  def self.valid_server_info(project_id, zone_name, instance_name)
    info = server_info(project_id, zone_name, instance_name)
    return nil unless info
    return nil if check_server_info(info).size() > 0
    info
  end

  def self.valid_ip_address(project_id, zone_name, instance_name)
    ip_address(valid_server_info(project_id, zone_name, instance_name))
  end

  def self.server_info(project_id, zone_name, instance_name)
    jsonText = IO.popen("gcloud compute --project #{project_id} instances list --zones #{zone_name} --format json") do |io|
      io.read()
    end
    serverInfoList = JSON.parse(jsonText) rescue nil
    return nil unless serverInfoList
    serverInfoList.select{|obj| obj["name"] == instance_name}.first
  end

  def self.check_server_info(info)
    cautions = []
    unless info["machineType"] == "n1-highcpu-4"
      cautions << "マシンタイプは n1-highcpu-4 を選択してください"
    end
    if info["disks"].any?{|d| d["type"] != "PERSISTENT"}
      cautions << "ディスクタイプは PERSISTENT を選択してください"
    end
    unless ip_address(info)
      cautions << "EXTERNAL IPアドレスが確認できません"
    end
    cautions
  end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,7 +13,7 @@
   end
 
   def self.server_info(project_id, zone_name, instance_name)
-    jsonText = IO.popen("gcloud compute --project #{project_id} instances list --zones #{zone_name} --format json") do |io|
+    jsonText = IO.popen([*%w(gcloud compute --project), project_id, %w(instances list --zones), zone_name, %w(--format json)]) do |io|
       io.read()
     end
     serverInfoList = JSON.parse(jsonText) rescue nil
```
