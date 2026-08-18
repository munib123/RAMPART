# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 35_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `35_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1019-1059 of the vulnerable file.

	layer_w = s_map->layers[layer].width;
	layer_h = s_map->layers[layer].height;
	for (i_x = 0; i_x < layer_w; ++i_x) for (i_y = 0; i_y < layer_h; ++i_y) {
		tile = &s_map->layers[layer].tilemap[i_x + i_y * layer_w];
		if (tile->tile_index == old_index)
			tile->tile_index = new_index;
	}
}

bool
layer_resize(int layer, int x_size, int y_size)
{
	int                 old_height;
	int                 old_width;
	struct map_tile*    tile;
	int                 tile_width;
	int                 tile_height;
	struct map_tile*    tilemap;
	struct map_trigger* trigger;
	struct map_zone*    zone;

	int x, y, i;

	old_width = s_map->layers[layer].width;
	old_height = s_map->layers[layer].height;

	// allocate a new tilemap and copy the old layer tiles into it.  we can't simply realloc
	// because the tilemap is a 2D array.
	if (!(tilemap = malloc(x_size * y_size * sizeof(struct map_tile))))
		return false;
	for (x = 0; x < x_size; ++x) {
		for (y = 0; y < y_size; ++y) {
			if (x < old_width && y < old_height) {
				tilemap[x + y * x_size] = s_map->layers[layer].tilemap[x + y * old_width];
			}
			else {
				tile = &tilemap[x + y * x_size];
				tile->frames_left = tileset_get_delay(s_map->tileset, 0);
				tile->tile_index = 0;
			}
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1036,6 +1036,7 @@
 	struct map_tile*    tilemap;
 	struct map_trigger* trigger;
 	struct map_zone*    zone;
+	size_t              tilemap_size;
 
 	int x, y, i;
 
@@ -1044,7 +1045,9 @@
 
 	// allocate a new tilemap and copy the old layer tiles into it.  we can't simply realloc
 	// because the tilemap is a 2D array.
-	if (!(tilemap = malloc(x_size * y_size * sizeof(struct map_tile))))
+	tilemap_size = x_size * y_size * sizeof(struct map_tile);
+	if (x_size == 0 || tilemap_size / x_size / sizeof(struct map_tile) != y_size
+		|| !(tilemap = malloc(tilemap_size)))
 		return false;
 	for (x = 0; x < x_size; ++x) {
 		for (y = 0; y < y_size; ++y) {
```
