# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in ruby
**Pair ID:** 735_4
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `735_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```ruby
Lines 8-41 of the vulnerable file.

  module Redis
    extend Forwardable

    def_delegator  :publisher, :publish
    def_delegators :subscriber, :subscribe
    def_delegators :regular_connection, :hgetall, :hdel, :hset, :hincrby

    private

    def regular_connection
      @regular_connection ||= new_connection
    end

    def publisher
      @publisher ||= new_connection
    end

    def subscriber
      @subscriber ||= new_connection.pubsub.tap do |c|
        c.on(:message) do |channel, message|
          message = Oj.load(message)
          c = Channel.from message['channel']
          c.dispatch message, channel
        end
      end
    end

    def new_connection
      EM::Hiredis.connect Slanger::Config.redis_address
    end

    extend self
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,7 @@
     def subscriber
       @subscriber ||= new_connection.pubsub.tap do |c|
         c.on(:message) do |channel, message|
-          message = Oj.load(message)
+          message = Oj.strict_load(message)
           c = Channel.from message['channel']
           c.dispatch message, channel
         end
```
