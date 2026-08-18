# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in json
**Pair ID:** 4111_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4111_2`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```json
Lines 167-207 of the vulnerable file.

                    "200": {
                        "description": "Successful Response",
                        "content": {
                            "application/json": {
                                "schema": {}
                            }
                        }
                    },
                    "422": {
                        "description": "Validation Error",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/HTTPValidationError"
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "components": {
        "schemas": {
            "AModel": {
                "title": "AModel",
                "required": [
                    "an_enum_value",
                    "aCamelDateTime",
                    "a_date"
                ],
                "type": "object",
                "properties": {
                    "an_enum_value": {
                        "$ref": "#/components/schemas/AnEnum"
                    },
                    "nested_list_of_enums": {
                        "title": "Nested List Of Enums",
                        "type": "array",
                        "items": {
                            "type": "array",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -184,6 +184,156 @@
                     }
                 }
             }
+        },
+        "/tests/test_defaults": {
+            "post": {
+                "tags": [
+                    "tests"
+                ],
+                "summary": "Test Defaults",
+                "operationId": "test_defaults_tests_test_defaults_post",
+                "parameters": [
+                    {
+                        "required": false,
+                        "schema": {
+                            "title": "String Prop",
+                            "type": "string",
+                            "default": "the default string"
+                        },
+                        "name": "string_prop",
+                        "in": "query"
+                    },
+                    {
+                        "required": false,
+                        "schema": {
+                            "title": "Datetime Prop",
+                            "type": "string",
+                            "format": "date-time",
+                            "default": "1010-10-10T00:00:00"
+                        },
+                        "name": "datetime_prop",
+                        "in": "query"
+                    },
+                    {
+                        "required": false,
+                        "schema": {
+                            "title": "Date Prop",
+                            "type": "string",
+                            "format": "date",
+                            "default": "1010-10-10"
+                        },
+                        "name": "date_prop",
+                        "in": "query"
+                    },
+                    {
+                        "required": false,
+                        "schema": {
+                            "title": "Float Prop",
+                            "type": "number",
+                            "default": 3.14
+                        },
+                        "name": "float_prop",
+                        "in": "query"
+                    },
+                    {
+                        "required": false,
+                        "schema": {
+                            "title": "Int Prop",
+                            "type": "integer",
+                            "default": 7
+                        },
+                        "name": "int_prop",
+                        "in": "query"
+                    },
+                    {
+                        "required": false,
+                        "schema": {
+                            "title": "Boolean Prop",
+                            "type": "boolean",
+                            "default": false
+                        },
+                        "name": "boolean_prop",
+                        "in": "query"
+                    },
+                    {
+                        "required": false,
+                        "schema": {
+                            "title": "List Prop",
+                            "type": "array",
+                            "items": {
+                                "$ref": "#/components/schemas/AnEnum"
+                            },
+                            "default": [
+                                "FIRST_VALUE",
+                                "SECOND_VALUE"
+                            ]
+                        },
+                        "name": "list_prop",
+                        "in": "query"
+                    },
+                    {
+                        "required": false,
+                        "schema": {
+                            "title": "Union Prop",
+                            "anyOf": [
+                                {
+                                    "type": "number"
+                                },
+                                {
+                                    "type": "string"
+                                }
+                            ],
+                            "default": "not a float"
+                        },
+                        "name": "union_prop",
+                        "in": "query"
+                    },
+                    {
+                        "required": false,
+                        "schema": {
+                            "$ref": "#/components/schemas/AnEnum"
+                        },
+                        "name": "enum_prop",
+                        "in": "query"
+                    }
+                ],
+                "requestBody": {
+                    "content": {
+                        "application/json": {
+                            "schema": {
+                                "title": "Dict Prop",
+                                "type": "object",
+                                "additionalProperties": {
+                                    "type": "string"
+                                },
+                                "default": {
+                                    "key": "val"
+                                }
+                            }
+                        }
+                    }
+                },
+                "responses": {
+                    "200": {
+                        "description": "Successful Response",
+                        "content": {
+                            "application/json": {
+                                "schema": {}
+                            }
+                        }
+                    },
+                    "422": {
+                        "description": "Validation Error",
+                        "content": {
+                            "application/json": {
+                                "schema": {
+                                    "$ref": "#/components/schemas/HTTPValidationError"
+                                }
+                            }
+                        }
+                    }
+                }
+            }
         }
     },
     "components": {
@@ -192,6 +342,7 @@
                 "title": "AModel",
                 "required": [
                     "an_enum_value",
+                    "some_dict",
                     "aCamelDateTime",
                     "a_date"
                 ],
@@ -216,8 +367,7 @@
                         "type": "object",
                         "additionalProperties": {
                             "type": "string"
-                        },
-                        "default": {}
+                        }
                     },
                     "aCamelDateTime": {
                         "title": "Acameldatetime",
```
