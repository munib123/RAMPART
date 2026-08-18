# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in java
**Pair ID:** 5220_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5220_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```java
Lines 1-22 of the vulnerable file.

/*
 * Copyright 2013-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.data.jpa.domain;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /*
- * Copyright 2013-2015 the original author or authors.
+ * Copyright 2013-2016 the original author or authors.
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -32,6 +32,7 @@
  * 
  * @author Thomas Darimont
  * @author Oliver Gierke
+ * @author Christoph Strobl
  */
 public class JpaSort extends Sort {
 
@@ -83,6 +84,10 @@
 		super(combine(orders, direction, paths));
 	}
 
+	private JpaSort(List<Order> orders) {
+		super(orders);
+	}
+
 	/**
 	 * Returns a new {@link JpaSort} with the given sorting criteria added to the current one.
 	 * 
@@ -118,6 +123,30 @@
 	}
 
 	/**
+	 * Returns a new {@link JpaSort} with the given sorting criteria added to the current one.
+	 *
+	 * @param direction can be {@literal null}.
+	 * @param properties must not be {@literal null} or empty.
+	 * @return
+	 */
+	public JpaSort andUnsafe(Direction direction, String... properties) {
+
+		Assert.notEmpty(properties, "Properties must not be null!");
+
+		List<Order> orders = new ArrayList<Order>();
+
+		for (Order order : this) {
+			orders.add(order);
+		}
+
+		for (String property : properties) {
+			orders.add(new JpaOrder(direction, property));
+		}
+
+		return new JpaSort(orders, direction, Collections.<Path<?, ?>> emptyList());
+	}
+
+	/**
 	 * Turns the given {@link Attribute}s into {@link Path}s.
 	 * 
 	 * @param attributes must not be {@literal null} or empty.
@@ -172,6 +201,51 @@
 
 		Assert.notNull(attribute, "Attribute must not be null!");
 		return new Path<T, S>(Arrays.asList(attribute));
+	}
+
+	/**
+	 * Creates new unsafe {@link JpaSort} based on given properties.
+	 *
+	 * @param properties must not be {@literal null} or empty.
+	 * @return
+	 */
+	public static JpaSort unsafe(String... properties) {
+		return unsafe(Sort.DEFAULT_DIRECTION, properties);
+	}
+
+	/**
+	 * Creates new unsafe {@link JpaSort} based on given {@link Direction} and properties.
+	 *
+	 * @param direction must not be {@literal null}.
+	 * @param properties must not be {@literal null} or empty.
+	 * @return
+	 */
+	public static JpaSort unsafe(Direction direction, String... properties) {
+
+		Assert.notNull(direction, "Direction must not be null!");
+		Assert.notEmpty(properties, "Properties must not be empty!");
+		Assert.noNullElements(properties, "Properties must not contain null values!");
+
+		return unsafe(direction, Arrays.asList(properties));
+	}
+
+	/**
+	 * Creates new unsafe {@link JpaSort} based on given {@link Direction} and properties.
+	 *
+	 * @param direction must not be {@literal null}.
+	 * @param properties must not be {@literal null} or empty.
+	 * @return
+	 */
+	public static JpaSort unsafe(Direction direction, List<String> properties) {
+
+		Assert.notEmpty(properties, "Properties must not be empty!");
+
+		List<Order> orders = new ArrayList<Order>();
+		for (String property : properties) {
+			orders.add(new JpaOrder(direction, property));
+		}
+
+		return new JpaSort(orders);
 	}
 
 	/**
@@ -233,4 +307,131 @@
 			return builder.length() == 0 ? "" : builder.substring(0, builder.lastIndexOf("."));
 		}
 	}
+
+	/**
+	 * @author Christoph Strobl
+	 */
+	public static class JpaOrder extends Order {
+
+		private final boolean unsafe;
+		private final boolean ignoreCase;
+
+		/**
+		 * Creates a new {@link JpaOrder} instance. if order is {@literal null} then order defaults to
+		 * {@link Sort#DEFAULT_DIRECTION}
+		 *
+		 * @param direction can be {@literal null}, will default to {@link Sort#DEFAULT_DIRECTION}.
+		 * @param property must not be {@literal null}.
+		 */
+		private JpaOrder(Direction direction, String property) {
+			this(direction, property, NullHandling.NATIVE);
+		}
+
+		/**
+		 * Creates a new {@link Order} instance. if order is {@literal null} then order defaults to
+		 * {@link Sort#DEFAULT_DIRECTION}.
+		 *
+		 * @param direction can be {@literal null}, will default to {@link Sort#DEFAULT_DIRECTION}.
+		 * @param property must not be {@literal null}.
+		 * @param nullHandlingHint can be {@literal null}, will default to {@link NullHandling#NATIVE}.
+		 */
+		private JpaOrder(Direction direction, String property, NullHandling nullHandlingHint) {
+			this(direction, property, nullHandlingHint, false, true);
+		}
+
+		private JpaOrder(Direction direction, String property, NullHandling nullHandling, boolean ignoreCase,
+				boolean unsafe) {
+
+			super(direction, property, nullHandling);
+			this.ignoreCase = ignoreCase;
+			this.unsafe = unsafe;
+		}
+
+		/*
+		 * (non-Javadoc)
+		 * @see org.springframework.data.domain.Sort.Order#with(org.springframework.data.domain.Sort.Direction)
+		 */
+		@Override
+		public JpaOrder with(Direction order) {
+			return new JpaOrder(order, getProperty(), getNullHandling(), isIgnoreCase(), this.unsafe);
+		}
+
+		/*
+		 * (non-Javadoc)
+		 * @see org.springframework.data.domain.Sort.Order#with(org.springframework.data.domain.Sort.NullHandling)
+		 */
+		@Override
+		public JpaOrder with(NullHandling nullHandling) {
+			return new JpaOrder(getDirection(), getProperty(), nullHandling, isIgnoreCase(), this.unsafe);
+		}
+
+		/*
+		 * (non-Javadoc)
+		 * @see org.springframework.data.domain.Sort.Order#nullsFirst()
+		 */
+		@Override
+		public JpaOrder nullsFirst() {
+			return with(NullHandling.NULLS_FIRST);
+		}
+
+		/*
+		 * (non-Javadoc)
+		 * @see org.springframework.data.domain.Sort.Order#nullsLast()
+		 */
+		@Override
+		public JpaOrder nullsLast() {
+			return with(NullHandling.NULLS_LAST);
+		}
+
+		/*
+		 * (non-Javadoc)
+		 * @see org.springframework.data.domain.Sort.Order#nullsNative()
+		 */
+		public JpaOrder nullsNative() {
+			return with(NullHandling.NATIVE);
+		}
+
+		/**
+		 * Creates new {@link Sort} with potentially unsafe {@link Order} instances.
+		 *
+		 * @param properties must not be {@literal null}.
+		 * @return
+		 */
+		public Sort withUnsafe(String... properties) {
+
+			Assert.notEmpty(properties, "Properties must not be empty!");
+			Assert.noNullElements(properties, "Properties must not contain null values!");
+
+			List<Order> orders = new ArrayList<Order>();
+			for (String property : properties) {
+				orders.add(new JpaOrder(getDirection(), property, getNullHandling(), isIgnoreCase(), this.unsafe));
+			}
+			return new Sort(orders);
+		}
+
+		/*
+		 * (non-Javadoc)
+		 * @see org.springframework.data.domain.Sort.Order#ignoreCase()
+		 */
+		@Override
+		public JpaOrder ignoreCase() {
+			return new JpaOrder(getDirection(), getProperty(), getNullHandling(), true, this.unsafe);
+		}
+
+		/*
+		 * (non-Javadoc)
+		 * @see org.springframework.data.domain.Sort.Order#isIgnoreCase()
+		 */
+		@Override
+		public boolean isIgnoreCase() {
+			return super.isIgnoreCase() || ignoreCase;
+		}
+
+		/**
+		 * @return true if {@link JpaOrder} created {@link #withUnsafe(String...)}.
+		 */
+		public boolean isUnsafe() {
+			return unsafe;
+		}
+	}
 }
```
