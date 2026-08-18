# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in ruby
**Pair ID:** 735_3
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `735_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```ruby
Lines 15-55 of the vulnerable file.

    def_delegators :channel, :push

    # Send an event received from Redis to the EventMachine channel
    def dispatch(message, channel)
      if channel =~ /\Aslanger:/
        # Messages received from the Redis channel slanger:*  carry info on
        # subscriptions. Update our subscribers accordingly.
        update_subscribers message
      else
        push Oj.dump(message, mode: :compat)
      end
    end

    def initialize(attrs)
      super
      # Also subscribe the slanger daemon to a Redis channel used for events concerning subscriptions.
      Slanger::Redis.subscribe 'slanger:connection_notification'
    end

    def subscribe(msg, callback, &blk)
      channel_data = Oj.load msg['data']['channel_data']
      public_subscription_id = SecureRandom.uuid

      # Send event about the new subscription to the Redis slanger:connection_notification Channel.
      publisher = publish_connection_notification subscription_id: public_subscription_id, online: true,
        channel_data: channel_data, channel: channel_id

      # Associate the subscription data to the public id in Redis.
      roster_add public_subscription_id, channel_data

      # fuuuuuuuuuccccccck!
      publisher.callback do
        EM.next_tick do
          # The Subscription event has been sent to Redis successfully.
          # Call the provided callback.
          callback.call
          # Add the subscription to our table.
          internal_subscription_table[public_subscription_id] = channel.subscribe &blk
        end
      end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,7 @@
     end
 
     def subscribe(msg, callback, &blk)
-      channel_data = Oj.load msg['data']['channel_data']
+      channel_data = Oj.strict_load msg['data']['channel_data']
       public_subscription_id = SecureRandom.uuid
 
       # Send event about the new subscription to the Redis slanger:connection_notification Channel.
```
