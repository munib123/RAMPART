# CrossVul Fix Pair: Origin Validation Error in c
**Pair ID:** 3125_1
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3125_1`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```c
Lines 1-22 of the vulnerable file.

//
//  OTRXMPPMessageYapStroage.h
//  ChatSecure
//
//  Created by David Chiles on 8/13/15.
//  Copyright (c) 2015 Chris Ballinger. All rights reserved.
//

@import XMPPFramework;
@import YapDatabase;
@class XMPPMessage;

NS_ASSUME_NONNULL_BEGIN
@interface OTRXMPPMessageYapStroage : XMPPModule

@property (nonatomic, strong, readonly) YapDatabaseConnection *databaseConnection;

/** This connection is only used for readWrites */
- (instancetype)initWithDatabaseConnection:(YapDatabaseConnection *)databaseConnection;

@end
NS_ASSUME_NONNULL_END
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,6 +14,7 @@
 @interface OTRXMPPMessageYapStroage : XMPPModule
 
 @property (nonatomic, strong, readonly) YapDatabaseConnection *databaseConnection;
+@property (nonatomic, readonly) dispatch_queue_t moduleDelegateQueue;
 
 /** This connection is only used for readWrites */
 - (instancetype)initWithDatabaseConnection:(YapDatabaseConnection *)databaseConnection;
```
