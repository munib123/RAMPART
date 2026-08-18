# CrossVul Fix Pair: Uncontrolled Resource Consumption in scala
**Pair ID:** 1930_3
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** scala
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1930_3`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```scala
Lines 3-43 of the vulnerable file.

 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.http4s.blaze.channel.nio1

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels._
import java.util.concurrent.RejectedExecutionException

import org.http4s.blaze.channel.ChannelHead
import org.http4s.blaze.pipeline.Command.{Disconnected, EOF}
import org.http4s.blaze.util
import org.http4s.blaze.util.BufferTools

import scala.annotation.tailrec
import scala.concurrent.{Future, Promise}
import scala.util.{Failure, Success, Try}

private[nio1] object NIO1HeadStage {
  private val CachedSuccess = Success(())

  private sealed trait WriteResult
  private case object Complete extends WriteResult
  private case object Incomplete extends WriteResult
  private case class WriteError(t: Exception) extends WriteResult // EOF signals normal termination

  /** Performs the read operation
    *
    * @param scratch a ByteBuffer in which to load read data. The method
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,7 +20,6 @@
 import java.nio.ByteBuffer
 import java.nio.channels._
 import java.util.concurrent.RejectedExecutionException
-
 import org.http4s.blaze.channel.ChannelHead
 import org.http4s.blaze.pipeline.Command.{Disconnected, EOF}
 import org.http4s.blaze.util
@@ -46,7 +45,7 @@
     * @return a `Try` representing successfully loading data into `scratch`, or
     *         the failure cause.
     */
-  private def performRead(ch: SocketChannel, scratch: ByteBuffer, size: Int): Try[Unit] =
+  private def performRead(ch: NIO1ClientChannel, scratch: ByteBuffer, size: Int): Try[Unit] =
     try {
       scratch.clear()
       if (size >= 0 && size < scratch.remaining)
@@ -69,7 +68,7 @@
     * @return a WriteResult that is one of Complete, Incomplete or WriteError(e: Exception)
     */
   private def performWrite(
-      ch: SocketChannel,
+      ch: NIO1ClientChannel,
       scratch: ByteBuffer,
       buffers: Array[ByteBuffer]): WriteResult =
     try if (BufferTools.areDirectOrEmpty(buffers)) {
@@ -116,12 +115,25 @@
 }
 
 private[nio1] final class NIO1HeadStage(
-    ch: SocketChannel,
+    ch: NIO1ClientChannel,
     selectorLoop: SelectorLoop,
     key: SelectionKey
 ) extends ChannelHead
     with Selectable {
   import NIO1HeadStage._
+
+  @deprecated(
+    "Binary compatibility shim. This one can leak connection acceptance permits.",
+    "0.14.15")
+  private[NIO1HeadStage] def this(
+      ch: SocketChannel,
+      selectorLoop: SelectorLoop,
+      key: SelectionKey
+  ) = this(
+    new NIO1ClientChannel(ch, () => ()),
+    selectorLoop: SelectorLoop,
+    key
+  )
 
   override def name: String = "NIO1 ByteBuffer Head Stage"
 
```
