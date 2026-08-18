# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 3492_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3492_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 440-480 of the vulnerable file.

        cycles = Array.new
        1.upto(nr_cycles) do |i|
          list = Array.new
          packages.each do |package,cycle|
            list.push(package) if cycle == i
          end
          cycles << list.sort
        end
        @repocycles[repository.name][arch.text] = cycles unless cycles.empty?
      end
    end
  end

  def rebuild_time
    required_parameters :repository, :arch
    load_packages_mainpage 
    @repository = params[:repository]
    @arch = params[:arch]
    @hosts = begin Integer(params[:hosts] || '40') rescue 40 end
    @scheduler = params[:scheduler] || 'needed'
    bdep = find_cached(BuilddepInfo, :project => @project.name, :repository => @repository, :arch => @arch)
    jobs = find_cached(Jobhislist , :project => @project.name, :repository => @repository, :arch => @arch, 
            :limit => @packages.each.size * 3, :code => ['succeeded', 'unchanged'])
    unless bdep and jobs
      flash[:error] = "Could not collect infos about repository #{@repository}/#{@arch}"
      redirect_to :action => :show, :project => @project
      return
    end
    indir = Dir.mktmpdir 
    f = File.open(indir + "/_builddepinfo.xml", 'w')
    f.write(bdep.dump_xml) 
    f.close
    f = File.open(indir + "/_jobhistory.xml", 'w')
    f.write(jobs.dump_xml)
    f.close
    outdir = Dir.mktmpdir
    cmd="perl ./mkdiststats '--srcdir=#{indir}' '--destdir=#{outdir}' --outfmt=xml #{@project.name}/#{@repository}/#{@arch} --width=910 --buildhosts=#{@hosts} --scheduler=#{@scheduler}"
    logger.debug "cd #{RAILS_ROOT}/vendor/diststats && #{cmd}"
    system("cd #{RAILS_ROOT}/vendor/diststats && #{cmd}")
    f=File.open(outdir + "/rebuild.png")
    png=f.read
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -457,6 +457,11 @@
     @arch = params[:arch]
     @hosts = begin Integer(params[:hosts] || '40') rescue 40 end
     @scheduler = params[:scheduler] || 'needed'
+    unless ["fifo", "lifo", "random", "btime", "needed", "neededb", "longest_data", "longested_triedread", "longest"].include? @scheduler
+      flash[:error] = "Invalid scheduler type, check mkdiststats docu - aehm, source"
+      redirect_to :action => :show, :project => @project
+      return
+    end
     bdep = find_cached(BuilddepInfo, :project => @project.name, :repository => @repository, :arch => @arch)
     jobs = find_cached(Jobhislist , :project => @project.name, :repository => @repository, :arch => @arch, 
             :limit => @packages.each.size * 3, :code => ['succeeded', 'unchanged'])
@@ -473,9 +478,16 @@
     f.write(jobs.dump_xml)
     f.close
     outdir = Dir.mktmpdir
-    cmd="perl ./mkdiststats '--srcdir=#{indir}' '--destdir=#{outdir}' --outfmt=xml #{@project.name}/#{@repository}/#{@arch} --width=910 --buildhosts=#{@hosts} --scheduler=#{@scheduler}"
-    logger.debug "cd #{RAILS_ROOT}/vendor/diststats && #{cmd}"
-    system("cd #{RAILS_ROOT}/vendor/diststats && #{cmd}")
+    logger.debug "cd #{RAILS_ROOT}/vendor/diststats && perl ./mkdiststats --srcdir=#{indir} --destdir=#{outdir} 
+             --outfmt=xml #{@project.name}/#{@repository}/#{@arch} --width=910
+             --buildhosts=#{@hosts} --scheduler=#{@scheduler}"
+    fork do
+      Dir.chdir("#{RAILS_ROOT}/vendor/diststats")
+      system("perl", "./mkdiststats", "--srcdir=#{indir}", "--destdir=#{outdir}", 
+             "--outfmt=xml", "#{@project.name}/#{@repository}/#{@arch}", "--width=910",
+             "--buildhosts=#{@hosts}", "--scheduler=#{@scheduler}")
+    end
+    Process.wait
     f=File.open(outdir + "/rebuild.png")
     png=f.read
     f.close 
```
