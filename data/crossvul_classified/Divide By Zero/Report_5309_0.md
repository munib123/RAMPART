# CrossVul Fix Pair: Divide By Zero in cpp
**Pair ID:** 5309_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5309_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```cpp
Lines 40-80 of the vulnerable file.


    // Horizontal
    appendImages( &appended, imageList.begin(), imageList.end() );
    // appended.display();
    if (( appended.signature() != "3a90bb0bb8f69f6788ab99e9e25598a0d6c5cdbbb797f77ad68011e0a8b1689d" ) &&
        ( appended.signature() != "c15fcd1e739b73638dc4e36837bdb53f7087359544664caf7b1763928129f3c7" ) &&
        ( appended.signature() != "229ff72f812e5f536245dc3b4502a0bc2ab2363f67c545863a85ab91ebfbfb83" ) &&
        ( appended.signature() != "b98c42c55fc4e661cb3684154256809c03c0c6b53da2738b6ce8066e1b6ddef0" ))
      {
	++failures;
	cout << "Line: " << __LINE__
	     << "  Horizontal append failed, signature = "
	     << appended.signature() << endl;
	appended.write("appendImages_horizontal_out.miff");
	// appended.display();
      }

    // Vertical
    appendImages( &appended, imageList.begin(), imageList.end(), true );
    if (( appended.signature() != "d73d25ccd6011936d08b6d0d89183b7a61790544c2195269aff4db2f782ffc08" ) &&
        ( appended.signature() != "0909f7ffa7c6ea410fb2ebfdbcb19d61b19c4bd271851ce3bd51662519dc2b58" ) &&
        ( appended.signature() != "11b97ba6ac1664aa1c2faed4c86195472ae9cce2ed75402d975bb4ffcf1de751" ) &&
        ( appended.signature() != "cae4815eeb3cb689e73b94d897a9957d3414d1d4f513e8b5e52579b05d164bfe" ))
      {
	++failures;
	cout << "Line: " << __LINE__
	     << "  Vertical append failed, signature = "
	     << appended.signature() << endl;
	appended.write("appendImages_vertical_out.miff");
	// appended.display();
      }
    
  }

  catch( Exception &error_ )
    {
      cout << "Caught exception: " << error_.what() << endl;
      return 1;
    }
  catch( exception &error_ )
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,7 +57,7 @@
     // Vertical
     appendImages( &appended, imageList.begin(), imageList.end(), true );
     if (( appended.signature() != "d73d25ccd6011936d08b6d0d89183b7a61790544c2195269aff4db2f782ffc08" ) &&
-        ( appended.signature() != "0909f7ffa7c6ea410fb2ebfdbcb19d61b19c4bd271851ce3bd51662519dc2b58" ) &&
+        ( appended.signature() != "f3590c183018757da798613a23505ab9600b35935988eee12f096cb6219f2bc3" ) &&
         ( appended.signature() != "11b97ba6ac1664aa1c2faed4c86195472ae9cce2ed75402d975bb4ffcf1de751" ) &&
         ( appended.signature() != "cae4815eeb3cb689e73b94d897a9957d3414d1d4f513e8b5e52579b05d164bfe" ))
       {
```
