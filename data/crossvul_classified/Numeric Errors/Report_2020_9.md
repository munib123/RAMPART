# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2020_9
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2020_9`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 497-537 of the vulnerable file.

	state.lenop = 64;
	state.curop = state.op = (char *) palloc(state.lenop);
	*(state.curop) = '\0';

	/* parse query & make polish notation (postfix, but in reverse order) */
	makepol(&state, pushval, opaque);

	close_tsvector_parser(state.valstate);

	if (list_length(state.polstr) == 0)
	{
		ereport(NOTICE,
				(errmsg("text-search query doesn't contain lexemes: \"%s\"",
						state.buffer)));
		query = (TSQuery) palloc(HDRSIZETQ);
		SET_VARSIZE(query, HDRSIZETQ);
		query->size = 0;
		return query;
	}

	/* Pack the QueryItems in the final TSQuery struct to return to caller */
	commonlen = COMPUTESIZE(list_length(state.polstr), state.sumlen);
	query = (TSQuery) palloc0(commonlen);
	SET_VARSIZE(query, commonlen);
	query->size = list_length(state.polstr);
	ptr = GETQUERY(query);

	/* Copy QueryItems to TSQuery */
	i = 0;
	foreach(cell, state.polstr)
	{
		QueryItem  *item = (QueryItem *) lfirst(cell);

		switch (item->type)
		{
			case QI_VAL:
				memcpy(&ptr[i], item, sizeof(QueryOperand));
				break;
			case QI_VALSTOP:
				ptr[i].type = QI_VALSTOP;
				break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -514,8 +514,13 @@
 		return query;
 	}
 
+	if (TSQUERY_TOO_BIG(list_length(state.polstr), state.sumlen))
+		ereport(ERROR,
+				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
+				 errmsg("tsquery is too large")));
+	commonlen = COMPUTESIZE(list_length(state.polstr), state.sumlen);
+
 	/* Pack the QueryItems in the final TSQuery struct to return to caller */
-	commonlen = COMPUTESIZE(list_length(state.polstr), state.sumlen);
 	query = (TSQuery) palloc0(commonlen);
 	SET_VARSIZE(query, commonlen);
 	query->size = list_length(state.polstr);
```
