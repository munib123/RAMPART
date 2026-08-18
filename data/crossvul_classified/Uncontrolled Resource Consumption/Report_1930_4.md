# CrossVul Fix Pair: Uncontrolled Resource Consumption in scala
**Pair ID:** 1930_4
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** scala
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1930_4`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```scala
Lines 19-49 of the vulnerable file.

import java.nio.channels.{SelectableChannel, SocketChannel}
import org.http4s.blaze.channel.SocketConnection
import java.net.SocketAddress

object NIO1Connection {
  def apply(connection: SelectableChannel): SocketConnection =
    connection match {
      case ch: SocketChannel => NIO1SocketConnection(ch)
      case _ =>
        // We don't know what type this is, so implement what we can
        new SocketConnection {
          override def remote: SocketAddress = local

          override def local: SocketAddress = new SocketAddress {}

          override def close(): Unit = connection.close()

          override def isOpen: Boolean = connection.isOpen
        }
    }
}

private case class NIO1SocketConnection(connection: SocketChannel) extends SocketConnection {
  override def remote: SocketAddress = connection.getRemoteAddress

  override def local: SocketAddress = connection.getLocalAddress

  override def isOpen: Boolean = connection.isConnected

  override def close(): Unit = connection.close()
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,6 +36,14 @@
           override def isOpen: Boolean = connection.isOpen
         }
     }
+
+  private[blaze] def apply(channel: NIO1ClientChannel): SocketConnection =
+    new SocketConnection {
+      override def remote: SocketAddress = channel.getRemoteAddress
+      override def local: SocketAddress = channel.getLocalAddress
+      override def isOpen: Boolean = channel.isOpen
+      override def close(): Unit = channel.close()
+    }
 }
 
 private case class NIO1SocketConnection(connection: SocketChannel) extends SocketConnection {
```
