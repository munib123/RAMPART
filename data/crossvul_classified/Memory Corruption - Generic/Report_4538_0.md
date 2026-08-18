# CrossVul Fix Pair: Out-of-bounds Write in csharp
**Pair ID:** 4538_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4538_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```csharp
Lines 27-67 of the vulnerable file.

        /// </summary>
        public static readonly MessagePackSecurity UntrustedData = new MessagePackSecurity
        {
            HashCollisionResistant = true,
            MaximumObjectGraphDepth = 500,
        };

        private readonly ObjectFallbackEqualityComparer objectFallbackEqualityComparer;

        private MessagePackSecurity()
        {
            this.objectFallbackEqualityComparer = new ObjectFallbackEqualityComparer(this);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MessagePackSecurity"/> class
        /// with properties copied from a provided template.
        /// </summary>
        /// <param name="copyFrom">The template to copy from.</param>
        protected MessagePackSecurity(MessagePackSecurity copyFrom)
        {
            if (copyFrom is null)
            {
                throw new ArgumentNullException(nameof(copyFrom));
            }

            this.HashCollisionResistant = copyFrom.HashCollisionResistant;
            this.MaximumObjectGraphDepth = copyFrom.MaximumObjectGraphDepth;
        }

        /// <summary>
        /// Gets a value indicating whether data to be deserialized is untrusted and thus should not be allowed to create
        /// dictionaries or other hash-based collections unless the hashed type has a hash collision resistant implementation available.
        /// This can mitigate some denial of service attacks when deserializing untrusted code.
        /// </summary>
        /// <value>
        /// The value is <c>false</c> for <see cref="TrustedData"/> and <c>true</c> for <see cref="UntrustedData"/>.
        /// </value>
        public bool HashCollisionResistant { get; private set; }

        /// <summary>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,6 +44,7 @@
         /// </summary>
         /// <param name="copyFrom">The template to copy from.</param>
         protected MessagePackSecurity(MessagePackSecurity copyFrom)
+            : this()
         {
             if (copyFrom is null)
             {
```
