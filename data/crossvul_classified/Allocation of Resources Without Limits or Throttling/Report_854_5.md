# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in java
**Pair ID:** 854_5
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `854_5`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```java
Lines 4-46 of the vulnerable file.

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

package com.facebook.thrift;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

import com.facebook.thrift.test.BigEnum;
import com.facebook.thrift.test.MySimpleStruct;
import com.facebook.thrift.test.SmallEnum;
import junit.framework.TestCase;
import org.junit.Test;

public class StructTest extends TestCase {
  @Test
  public void testStructHashcode() throws Exception {
    MySimpleStruct defaultStruct = new MySimpleStruct();
    assertThat(defaultStruct.hashCode(), is(not(equalTo(0))));

    MySimpleStruct struct1 = new MySimpleStruct(1, "Foo");
    MySimpleStruct struct2 = new MySimpleStruct(2, "Bar");

    assertThat(struct1.hashCode(), is(not(equalTo(0))));
    assertThat(struct2.hashCode(), is(not(equalTo(0))));
    assertThat(struct1.hashCode(), is(not(equalTo(struct2.hashCode()))));
  }

  @Test
  public void testSmallEnum() throws Exception {
    assertThat(SmallEnum.findByValue(SmallEnum.RED.getValue()), equalTo(SmallEnum.RED));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,9 +21,9 @@
 import static org.hamcrest.core.Is.is;
 import static org.junit.Assert.assertThat;
 
-import com.facebook.thrift.test.BigEnum;
-import com.facebook.thrift.test.MySimpleStruct;
-import com.facebook.thrift.test.SmallEnum;
+import com.facebook.thrift.java.test.BigEnum;
+import com.facebook.thrift.java.test.MySimpleStruct;
+import com.facebook.thrift.java.test.SmallEnum;
 import junit.framework.TestCase;
 import org.junit.Test;
 
```
