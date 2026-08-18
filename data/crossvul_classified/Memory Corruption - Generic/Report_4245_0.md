# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 4245_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4245_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 1296-1336 of the vulnerable file.

        // since we don't know where the file pointer is
        //
        int old_dx=dx;
        int old_dy=dy;
        int old_lx=lx;
        int old_ly=ly;
        if(isMultiPart(version()))
        {
            _data->_streamData->is->seekg(_data->tileOffsets(dx,dy,lx,ly));
        }
        readNextTileData (_data->_streamData, _data, dx, dy, lx, ly,
			  tileBuffer->buffer,
                          pixelDataSize);
        if(isMultiPart(version()))
        {
            if (old_dx!=dx || old_dy !=dy || old_lx!=lx || old_ly!=ly)
            {
                throw IEX_NAMESPACE::ArgExc ("rawTileData read the wrong tile");
            }
        }
        pixelData = tileBuffer->buffer;
    }
    catch (IEX_NAMESPACE::BaseExc &e)
    {
        REPLACE_EXC (e, "Error reading pixel data from image "
                     "file \"" << fileName() << "\". " << e.what());
        throw;
    }
}


unsigned int
TiledInputFile::tileXSize () const
{
    return _data->tileDesc.xSize;
}


unsigned int
TiledInputFile::tileYSize () const
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1313,6 +1313,13 @@
                 throw IEX_NAMESPACE::ArgExc ("rawTileData read the wrong tile");
             }
         }
+        else
+        {
+             if(!isValidTile (dx, dy, lx, ly) )
+             {
+                 throw IEX_NAMESPACE::IoExc ("rawTileData read an invalid tile");
+             }
+        }
         pixelData = tileBuffer->buffer;
     }
     catch (IEX_NAMESPACE::BaseExc &e)
```
