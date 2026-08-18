# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5041_7
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5041_7`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 33-73 of the vulnerable file.

        else
          def path(key)
            @path + "/" + @prefix  + "_" + key
          end
        end
      end

      EXPIRES_IN_SECONDS = 60 * 60 * 24

      def initialize(args = nil)
        args ||= {}
        @path = args[:path]
        @expires_in_seconds = args[:expires_in] || EXPIRES_IN_SECONDS
        raise ArgumentError.new :path unless @path
        FileUtils.mkdir_p(@path) unless ::File.exists?(@path)

        @timer_struct_cache = FileCache.new(@path, "mp_timers")
        @timer_struct_lock  = Mutex.new
        @user_view_cache    = FileCache.new(@path, "mp_views")
        @user_view_lock     = Mutex.new

        me = self
        t = CacheCleanupThread.new do
          interval = 10
          cleanup_cache_cycle = 3600
          cycle_count = 1

          begin
            until Thread.current[:should_exit] do
              # TODO: a sane retry count before bailing

              # We don't want to hit the filesystem every 10s to clean up the cache so we need to do a bit of
              # accounting to avoid sleeping that entire time.  We don't want to sleep for the entire period because
              # it means the thread will stay live in hot deployment scenarios, keeping a potentially large memory
              # graph from being garbage collected upon undeploy.
              if cycle_count * interval >= cleanup_cache_cycle
                cycle_count = 1
                me.cleanup_cache
              end

              sleep(interval)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,6 +50,9 @@
         @timer_struct_lock  = Mutex.new
         @user_view_cache    = FileCache.new(@path, "mp_views")
         @user_view_lock     = Mutex.new
+
+        @auth_token_cache    = FileCache.new(@path, "tokens")
+        @auth_token_lock     = Mutex.new
 
         me = self
         t = CacheCleanupThread.new do
@@ -126,6 +129,28 @@
         }
       end
 
+      def flush_tokens
+        @auth_token_lock.synchronize {
+          @auth_token_cache[""] = nil
+        }
+      end
+
+      def allowed_tokens
+        @auth_token_lock.synchronize {
+          token1, token2, cycle_at = @auth_token_cache[""]
+
+          unless cycle_at && (Time === cycle_at) && (cycle_at > Time.now)
+            token2 = token1
+            token1 = SecureRandom.hex
+            cycle_at = Time.now + Rack::MiniProfiler::AbstractStore::MAX_TOKEN_AGE
+          end
+
+          @auth_token_cache[""] = [token1, token2, cycle_at]
+
+          [token1, token2].compact
+        }
+      end
+
       def cleanup_cache
         files = Dir.entries(@path)
         @timer_struct_lock.synchronize {
```
