# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 2235_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2235_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 755-788 of the vulnerable file.

		/* Edge - print dimensions along */
		g_string_append_printf(str, "\t\"%p\" -> \"%p\" [label=\" %dx%d\"];\n",
			filter, next,
			rs_filter_response_get_width(response), rs_filter_response_get_height(response));
		g_object_unref(response);

		/* Recursively call ourself for every "next" filter */
		rs_filter_graph_helper(str, next);
	}
}

/**
 * Draw a nice graph of the filter chain
 * note: Requires graphviz
 * @param filter The top-most filter to graph
 */
void
rs_filter_graph(RSFilter *filter)
{
	g_return_if_fail(RS_IS_FILTER(filter));
	GString *str = g_string_new("digraph G {\n");

	rs_filter_graph_helper(str, filter);

	g_string_append_printf(str, "}\n");
	g_file_set_contents("/tmp/rs-filter-graph", str->str, str->len, NULL);

	if (0 != system("dot -Tpng >/tmp/rs-filter-graph.png </tmp/rs-filter-graph"))
		g_warning("Calling dot failed");
	if (0 != system("gnome-open /tmp/rs-filter-graph.png"))
		g_warning("Calling gnome-open failed.");

	g_string_free(str, TRUE);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -772,17 +772,32 @@
 rs_filter_graph(RSFilter *filter)
 {
 	g_return_if_fail(RS_IS_FILTER(filter));
+	gchar *dot_filename;
+	gchar *png_filename;
+	gchar *command_line;
 	GString *str = g_string_new("digraph G {\n");
 
 	rs_filter_graph_helper(str, filter);
 
 	g_string_append_printf(str, "}\n");
-	g_file_set_contents("/tmp/rs-filter-graph", str->str, str->len, NULL);
-
-	if (0 != system("dot -Tpng >/tmp/rs-filter-graph.png </tmp/rs-filter-graph"))
+
+	/* Here we would like to use g_mkdtemp(), but due to a bug in upstream, that's impossible */
+	dot_filename = g_strdup_printf("/tmp/rs-filter-graph.%u", g_random_int());
+	png_filename = g_strdup_printf("%s.%u.png", dot_filename, g_random_int());
+
+	g_file_set_contents(dot_filename, str->str, str->len, NULL);
+
+	command_line = g_strdup_printf("dot -Tpng >%s <%s", png_filename, dot_filename);
+	if (0 != system(command_line))
 		g_warning("Calling dot failed");
-	if (0 != system("gnome-open /tmp/rs-filter-graph.png"))
+	g_free(command_line);
+
+	command_line = g_strdup_printf("gnome-open %s", png_filename);
+	if (0 != system(command_line))
 		g_warning("Calling gnome-open failed.");
-
+	g_free(command_line);
+
+	g_free(dot_filename);
+	g_free(png_filename);
 	g_string_free(str, TRUE);
 }
```
