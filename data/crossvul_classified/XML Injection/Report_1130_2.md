# CrossVul Fix Pair: XML Injection (aka Blind XPath Injection) in java
**Pair ID:** 1130_2
**Vulnerability Class:** XML Injection
**CWE:** CWE-91
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1130_2`)

## Vulnerability Information & PoC

## Description
XML Injection (aka Blind XPath Injection) - Within XML, special elements could include reserved words or characters such as <, >, , and &, which could then be used to add new data or modify XML syntax.

## Vulnerable Code
```java
Lines 39-79 of the vulnerable file.

	 * @throws IllegalStateException if you add a value for a register that already has a value in the filter
	 */
	public void addRegAndValueToFilter(String contextRegister, BigInteger value) {
		if (contextRegisters.contains(contextRegister)) {
			throw new IllegalStateException("Filter can have only one value per register!");
		}
		contextRegisters.add(contextRegister);
		values.put(contextRegister, value);
	}

	/**
	 * Determines whether a list of {@link ContextRegisterInfo} objects passes the filter.
	 * 
	 * @param contextRegisterInfos
	 * @return {@code true} precisely when each {@link ContextRegisterInfo} in {@link ContextRegisterInfos} passes
	 * the filter.
	 */
	public boolean allows(List<ContextRegisterInfo> contextRegisterInfos) {
		for (ContextRegisterInfo cInfo : contextRegisterInfos) {
			if (contextRegisters.contains(cInfo.getContextRegister())) {
				if (!values.get(cInfo.getContextRegister()).equals(cInfo.getValueAsBigInteger())) {
					return false;
				}
			}
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Context Register Filter: \n");
		for (String cReg : contextRegisters) {
			sb.append(cReg);
			sb.append(": ");
			sb.append(values.get(cReg).toString());
			sb.append("\n");
		}
		sb.append("\n");
		return sb.toString();
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,7 +56,7 @@
 	public boolean allows(List<ContextRegisterInfo> contextRegisterInfos) {
 		for (ContextRegisterInfo cInfo : contextRegisterInfos) {
 			if (contextRegisters.contains(cInfo.getContextRegister())) {
-				if (!values.get(cInfo.getContextRegister()).equals(cInfo.getValueAsBigInteger())) {
+				if (!values.get(cInfo.getContextRegister()).equals(cInfo.getValue())) {
 					return false;
 				}
 			}
```
