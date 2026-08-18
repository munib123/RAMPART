# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 2311_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2311_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 4480-4520 of the vulnerable file.

    	}
    }

    /* loop reading the GPS coordinates */

    while( G.do_exit == 0 )
    {
        usleep( 500000 );
        memset( G.gps_loc, 0, sizeof( float ) * 5 );

        /* read position, speed, heading, altitude */
        if (is_json) {
        	// Format definition: http://catb.org/gpsd/gpsd_json.html

        	if (pos == sizeof( line )) {
        		memset(line, 0, sizeof(line));
        		pos = 0;
        	}

        	// New version, JSON
        	if( recv( gpsd_sock, line + pos, sizeof( line ) - 1, 0 ) <= 0 )
        		return;

        	// search for TPV class: {"class":"TPV"
        	temp = strstr(line, "{\"class\":\"TPV\"");
        	if (temp == NULL) {
        		continue;
        	}

        	// Make sure the data we have is complete
        	if (strchr(temp, '}') == NULL) {
        		// Move the data at the beginning of the buffer;
        		pos = strlen(temp);
        		if (temp != line) {
        			memmove(line, temp, pos);
        			memset(line + pos, 0, sizeof(line) - pos);
        		}
        	}

			// Example line: {"class":"TPV","tag":"MID2","device":"/dev/ttyUSB0","time":1350957517.000,"ept":0.005,"lat":46.878936576,"lon":-115.832602964,"alt":1968.382,"track":0.0000,"speed":0.000,"climb":0.000,"mode":3}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4497,7 +4497,7 @@
         	}
 
         	// New version, JSON
-        	if( recv( gpsd_sock, line + pos, sizeof( line ) - 1, 0 ) <= 0 )
+        	if( recv( gpsd_sock, line + pos, sizeof( line ) - pos - 1, 0 ) <= 0 )
         		return;
 
         	// search for TPV class: {"class":"TPV"
```
