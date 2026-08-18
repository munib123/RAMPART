# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in java
**Pair ID:** 184_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `184_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```java
Lines 9-49 of the vulnerable file.

 * the unrar licence applies to all junrar source and binary distributions
 * you are not allowed to use this source to re-create the RAR compression
 * algorithm
 *
 * Here some html entities which can be used for escaping javadoc tags:
 * "&":  "&#038;" or "&amp;"
 * "<":  "&#060;" or "&lt;"
 * ">":  "&#062;" or "&gt;"
 * "@":  "&#064;"
 */
package com.github.junrar;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.github.junrar.exception.RarException;
import com.github.junrar.exception.RarException.RarExceptionType;
import com.github.junrar.impl.FileVolumeManager;
import com.github.junrar.io.IReadOnlyAccess;
import com.github.junrar.rarfile.AVHeader;
import com.github.junrar.rarfile.BaseBlock;
import com.github.junrar.rarfile.BlockHeader;
import com.github.junrar.rarfile.CommentHeader;
import com.github.junrar.rarfile.EAHeader;
import com.github.junrar.rarfile.EndArcHeader;
import com.github.junrar.rarfile.FileHeader;
import com.github.junrar.rarfile.MacInfoHeader;
import com.github.junrar.rarfile.MainHeader;
import com.github.junrar.rarfile.MarkHeader;
import com.github.junrar.rarfile.ProtectHeader;
import com.github.junrar.rarfile.SignHeader;
import com.github.junrar.rarfile.SubBlockHeader;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,9 @@
 import java.io.PipedInputStream;
 import java.io.PipedOutputStream;
 import java.util.ArrayList;
+import java.util.HashSet;
 import java.util.List;
+import java.util.Set;
 import java.util.logging.Level;
 import java.util.logging.Logger;
 
@@ -62,6 +64,8 @@
 public class Archive implements Closeable {
 	private static Logger logger = Logger.getLogger(Archive.class.getName());
 
+	private static int MAX_HEADER_SIZE = 20971520;//20MB
+
 	private IReadOnlyAccess rof;
 
 	private final UnrarCallback unrarCallback;
@@ -229,11 +233,13 @@
 		headers.clear();
 		currentHeaderIndex = 0;
 		int toRead = 0;
-
+		//keep track of positions already processed for
+		//more robustness against corrupt files
+		Set<Long> processedPositions = new HashSet<Long>();
 		while (true) {
 			int size = 0;
 			long newpos = 0;
-			byte[] baseBlockBuffer = new byte[BaseBlock.BaseBlockSize];
+			byte[] baseBlockBuffer = safelyAllocate(BaseBlock.BaseBlockSize, MAX_HEADER_SIZE);
 
 			long position = rof.getPosition();
 
@@ -266,7 +272,7 @@
 			case MainHeader:
 				toRead = block.hasEncryptVersion() ? MainHeader.mainHeaderSizeWithEnc
 						: MainHeader.mainHeaderSize;
-				byte[] mainbuff = new byte[toRead];
+				byte[] mainbuff = safelyAllocate(toRead, MAX_HEADER_SIZE);
 				rof.readFully(mainbuff, toRead);
 				MainHeader mainhead = new MainHeader(block, mainbuff);
 				headers.add(mainhead);
@@ -280,7 +286,7 @@
 
 			case SignHeader:
 				toRead = SignHeader.signHeaderSize;
-				byte[] signBuff = new byte[toRead];
+				byte[] signBuff = safelyAllocate(toRead, MAX_HEADER_SIZE);
 				rof.readFully(signBuff, toRead);
 				SignHeader signHead = new SignHeader(block, signBuff);
 				headers.add(signHead);
@@ -290,7 +296,7 @@
 
 			case AvHeader:
 				toRead = AVHeader.avHeaderSize;
-				byte[] avBuff = new byte[toRead];
+				byte[] avBuff = safelyAllocate(toRead, MAX_HEADER_SIZE);
 				rof.readFully(avBuff, toRead);
 				AVHeader avHead = new AVHeader(block, avBuff);
 				headers.add(avHead);
@@ -299,7 +305,7 @@
 
 			case CommHeader:
 				toRead = CommentHeader.commentHeaderSize;
-				byte[] commBuff = new byte[toRead];
+				byte[] commBuff = safelyAllocate(toRead, MAX_HEADER_SIZE);
 				rof.readFully(commBuff, toRead);
 				CommentHeader commHead = new CommentHeader(block, commBuff);
 				headers.add(commHead);
@@ -307,6 +313,10 @@
 				// Integer.toHexString(commHead.getUnpMethod()));
 				newpos = commHead.getPositionInFile()
 						+ commHead.getHeaderSize();
+				if (processedPositions.contains(newpos)) {
+					throw new RarException(RarExceptionType.badRarArchive);
+				}
+				processedPositions.add(newpos);
 				rof.setPosition(newpos);
 
 				break;
@@ -321,7 +331,7 @@
 				}
 				EndArcHeader endArcHead;
 				if (toRead > 0) {
-					byte[] endArchBuff = new byte[toRead];
+					byte[] endArchBuff = safelyAllocate(toRead, MAX_HEADER_SIZE);
 					rof.readFully(endArchBuff, toRead);
 					endArcHead = new EndArcHeader(block, endArchBuff);
 					// logger.info("HeaderType: endarch\ndatacrc:"+
@@ -335,7 +345,7 @@
 				return;
 
 			default:
-				byte[] blockHeaderBuffer = new byte[BlockHeader.blockHeaderSize];
+				byte[] blockHeaderBuffer = safelyAllocate(BlockHeader.blockHeaderSize, MAX_HEADER_SIZE);
 				rof.readFully(blockHeaderBuffer, BlockHeader.blockHeaderSize);
 				BlockHeader blockHead = new BlockHeader(block,
 						blockHeaderBuffer);
@@ -346,13 +356,17 @@
 					toRead = blockHead.getHeaderSize()
 							- BlockHeader.BaseBlockSize
 							- BlockHeader.blockHeaderSize;
-					byte[] fileHeaderBuffer = new byte[toRead];
+					byte[] fileHeaderBuffer = safelyAllocate(toRead, MAX_HEADER_SIZE);
 					rof.readFully(fileHeaderBuffer, toRead);
 
 					FileHeader fh = new FileHeader(blockHead, fileHeaderBuffer);
 					headers.add(fh);
 					newpos = fh.getPositionInFile() + fh.getHeaderSize()
 							+ fh.getFullPackSize();
+					if (processedPositions.contains(newpos)) {
+						throw new RarException(RarExceptionType.badRarArchive);
+					}
+					processedPositions.add(newpos);
 					rof.setPosition(newpos);
 					break;
 
@@ -360,18 +374,21 @@
 					toRead = blockHead.getHeaderSize()
 							- BlockHeader.BaseBlockSize
 							- BlockHeader.blockHeaderSize;
-					byte[] protectHeaderBuffer = new byte[toRead];
+					byte[] protectHeaderBuffer = safelyAllocate(toRead, MAX_HEADER_SIZE);
 					rof.readFully(protectHeaderBuffer, toRead);
 					ProtectHeader ph = new ProtectHeader(blockHead,
 							protectHeaderBuffer);
-
 					newpos = ph.getPositionInFile() + ph.getHeaderSize()
 							+ ph.getDataSize();
+					if (processedPositions.contains(newpos)) {
+						throw new RarException(RarExceptionType.badRarArchive);
+					}
+					processedPositions.add(newpos);
 					rof.setPosition(newpos);
 					break;
 
 				case SubHeader: {
-					byte[] subHeadbuffer = new byte[SubBlockHeader.SubBlockHeaderSize];
+					byte[] subHeadbuffer = safelyAllocate(SubBlockHeader.SubBlockHeaderSize, MAX_HEADER_SIZE);
 					rof.readFully(subHeadbuffer,
 							SubBlockHeader.SubBlockHeaderSize);
 					SubBlockHeader subHead = new SubBlockHeader(blockHead,
@@ -379,7 +396,7 @@
 					subHead.print();
 					switch (subHead.getSubType()) {
 					case MAC_HEAD: {
-						byte[] macHeaderbuffer = new byte[MacInfoHeader.MacInfoHeaderSize];
+						byte[] macHeaderbuffer = safelyAllocate(MacInfoHeader.MacInfoHeaderSize, MAX_HEADER_SIZE);
 						rof.readFully(macHeaderbuffer,
 								MacInfoHeader.MacInfoHeaderSize);
 						MacInfoHeader macHeader = new MacInfoHeader(subHead,
@@ -393,7 +410,7 @@
 					case BEEA_HEAD:
 						break;
 					case EA_HEAD: {
-						byte[] eaHeaderBuffer = new byte[EAHeader.EAHeaderSize];
+						byte[] eaHeaderBuffer = safelyAllocate(EAHeader.EAHeaderSize, MAX_HEADER_SIZE);
 						rof.readFully(eaHeaderBuffer, EAHeader.EAHeaderSize);
 						EAHeader eaHeader = new EAHeader(subHead,
 								eaHeaderBuffer);
@@ -411,7 +428,7 @@
 						toRead -= BaseBlock.BaseBlockSize;
 						toRead -= BlockHeader.blockHeaderSize;
 						toRead -= SubBlockHeader.SubBlockHeaderSize;
-						byte[] uoHeaderBuffer = new byte[toRead];
+						byte[] uoHeaderBuffer = safelyAllocate(toRead, MAX_HEADER_SIZE);
 						rof.readFully(uoHeaderBuffer, toRead);
 						UnixOwnersHeader uoHeader = new UnixOwnersHeader(
 								subHead, uoHeaderBuffer);
@@ -432,6 +449,16 @@
 			}
 			// logger.info("\n--------end header--------");
 		}
+	}
+
+	private static byte[] safelyAllocate(long len, int maxSize) throws RarException {
+		if (maxSize < 0) {
+			throw new IllegalArgumentException("maxsize must be >= 0");
+		}
+		if (len < 0 || len > (long)maxSize) {
+			throw new RarException(RarExceptionType.badRarArchive);
+		}
+		return new byte[(int)len];
 	}
 
 	/**
```
