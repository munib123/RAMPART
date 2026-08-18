# CrossVul Fix Pair: Out-of-bounds Write in csharp
**Pair ID:** 4538_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4538_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```csharp
Lines 108-148 of the vulnerable file.


    [Fact]
    public void EqualityComparer_ObjectFallback()
    {
        var eq = MessagePackSecurity.UntrustedData.GetEqualityComparer<object>();

        Assert.Equal(eq.GetHashCode(null), eq.GetHashCode(null));
        Assert.NotEqual(eq.GetHashCode(null), eq.GetHashCode(new object()));

        Assert.Equal(eq.GetHashCode("hi"), eq.GetHashCode("hi"));
        Assert.NotEqual(eq.GetHashCode("hi"), eq.GetHashCode("bye"));

        Assert.Equal(eq.GetHashCode(true), eq.GetHashCode(true));
        Assert.NotEqual(eq.GetHashCode(true), eq.GetHashCode(false));

        var o = new object();
        Assert.Equal(eq.GetHashCode(o), eq.GetHashCode(o));
        Assert.NotEqual(eq.GetHashCode(o), eq.GetHashCode(new object()));
    }

    /// <summary>
    /// Verifies that arbitrary other types not known to be hash safe will be rejected.
    /// </summary>
    [Fact]
    public void EqualityComparer_ObjectFallback_UnsupportedType()
    {
        var eq = MessagePackSecurity.UntrustedData.GetEqualityComparer<object>();
        var ex = Assert.Throws<TypeAccessException>(() => eq.GetHashCode(new AggregateException()));
        this.Logger.WriteLine(ex.ToString());
    }

    [Fact]
    public void TypelessFormatterWithUntrustedData_SafeKeys()
    {
        var data = new
        {
            A = (byte)3,
            B = new Dictionary<object, byte>
            {
                { "C", 15 },
            },
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -125,6 +125,13 @@
         Assert.NotEqual(eq.GetHashCode(o), eq.GetHashCode(new object()));
     }
 
+    [Fact]
+    public void EqualityComparer_ObjectFallback_AfterCopyCtor()
+    {
+        var security = MessagePackSecurity.UntrustedData.WithMaximumObjectGraphDepth(15);
+        Assert.NotNull(security.GetEqualityComparer<object>());
+    }
+
     /// <summary>
     /// Verifies that arbitrary other types not known to be hash safe will be rejected.
     /// </summary>
```
