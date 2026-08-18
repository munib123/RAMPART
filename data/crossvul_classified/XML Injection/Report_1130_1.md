# CrossVul Fix Pair: XML Injection (aka Blind XPath Injection) in java
**Pair ID:** 1130_1
**Vulnerability Class:** XML Injection
**CWE:** CWE-91
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1130_1`)

## Vulnerability Information & PoC

## Description
XML Injection (aka Blind XPath Injection) - Within XML, special elements could include reserved words or characters such as <, >, , and &, which could then be used to add new data or modify XML syntax.

## Vulnerable Code
```java
Lines 26-66 of the vulnerable file.

	private Set<String> contextRegisters;//names of the context registers
	private Map<String, Set<BigInteger>> regsToValues;//for each register, a list of values it can take

	/**
	 * Create a empty {@link ContextRegisterExtent}
	 */
	public ContextRegisterExtent() {
		contextRegisters = new HashSet<String>();
		regsToValues = new HashMap<String, Set<BigInteger>>();
	}

	/**
	 * Accumulates the information in each element of {@code contextRegisterInfo} into the extent.
	 * @param contextRegisterInfo
	 */
	public void addContextInfo(List<ContextRegisterInfo> contextRegisterInfo) {
		if ((contextRegisterInfo == null) || (contextRegisterInfo.isEmpty())) {
			return;
		}
		for (ContextRegisterInfo cRegInfo : contextRegisterInfo) {
			addRegisterAndValue(cRegInfo.getContextRegister(), cRegInfo.getValueAsBigInteger());
		}
	}

	private void addRegisterAndValue(String register, BigInteger value) {
		if (!contextRegisters.contains(register)) {
			contextRegisters.add(register);
			Set<BigInteger> valueSet = new HashSet<BigInteger>();
			regsToValues.put(register, valueSet);
		}
		regsToValues.get(register).add(value);
	}

	/**
	 * Returns an alphabetized list of context registers.
	 * @return the list
	 */
	public List<String> getContextRegisters() {
		List<String> contextRegisterList = new ArrayList<String>(contextRegisters.size());
		contextRegisterList.addAll(contextRegisters);
		Collections.sort(contextRegisterList);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,7 +43,7 @@
 			return;
 		}
 		for (ContextRegisterInfo cRegInfo : contextRegisterInfo) {
-			addRegisterAndValue(cRegInfo.getContextRegister(), cRegInfo.getValueAsBigInteger());
+			addRegisterAndValue(cRegInfo.getContextRegister(), cRegInfo.getValue());
 		}
 	}
 
```
