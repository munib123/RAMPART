# CrossVul Fix Pair: Improper Access Control in ruby
**Pair ID:** 2381_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2381_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```ruby
Lines 119-159 of the vulnerable file.

        Grit::Commit.list_from_string(repo, log)
      end
      
    end
    
    # Note that in Grit, the methods grep, rm, checkout, ls_files
    # are all passed to native via method_missing. Hence the uniform
    # method signatures.
    class Git
    
      def initialize(git)
        @git = git
      end
      
      def exist?
        @git.exist?
      end
      
      def grep(query, options={})
        ref = options[:ref] ? options[:ref] : "HEAD"
        args = [{}, '-I', '-i', '-c', query, ref, '--']
        args << options[:path] if options[:path]
        result = @git.grep(*args).split("\n")
        result.map do |line|
          branch_and_name, _, count = line.rpartition(":")
          branch, _, name = branch_and_name.partition(':')
          {:name => name, :count => count}
        end
      end
      
      # git.rm({'f' => true}, '--', path)
      def rm(path, options = {}, &block)
        options['f'] = true if options[:force]
        @git.rm(options, '--', path, &block)
      end
      
      # git.checkout({}, 'HEAD', '--', path)
      def checkout(path, ref, options = {}, &block)
        @git.checkout(options, ref, '--', path, &block)
      end
      
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,6 +136,8 @@
       
       def grep(query, options={})
         ref = options[:ref] ? options[:ref] : "HEAD"
+        query = Shellwords.split(query).select {|q| !(q =~ /^(-O)|(--open-files-in-pager)/) }
+        query = Shellwords.join(query)
         args = [{}, '-I', '-i', '-c', query, ref, '--']
         args << options[:path] if options[:path]
         result = @git.grep(*args).split("\n")
@@ -165,6 +167,7 @@
       
       def ls_files(query, options = {})
         options[:ref] = options[:ref] ? options[:ref] : "HEAD"
+        query = Shellwords.shellescape(query)
         @git.ls_files({}, "*#{query}*").split("\n")
       end
       
```
