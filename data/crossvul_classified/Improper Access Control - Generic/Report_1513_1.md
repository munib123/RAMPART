# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1513_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1513_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 47-87 of the vulnerable file.

		} dw;
		struct {
			conf_word_write write;
			conf_word_read read;
		} w;
		struct {
			conf_byte_write write;
			conf_byte_read read;
		} b;
	} u;
	struct list_head list;
};

struct config_field_entry {
	struct list_head list;
	const struct config_field *field;
	unsigned int base_offset;
	void *data;
};

#define OFFSET(cfg_entry) ((cfg_entry)->base_offset+(cfg_entry)->field->offset)

/* Add fields to a device - the add_fields macro expects to get a pointer to
 * the first entry in an array (of which the ending is marked by size==0)
 */
int xen_pcibk_config_add_field_offset(struct pci_dev *dev,
				    const struct config_field *field,
				    unsigned int offset);

static inline int xen_pcibk_config_add_field(struct pci_dev *dev,
					   const struct config_field *field)
{
	return xen_pcibk_config_add_field_offset(dev, field, 0);
}

static inline int xen_pcibk_config_add_fields(struct pci_dev *dev,
					    const struct config_field *field)
{
	int i, err = 0;
	for (i = 0; field[i].size != 0; i++) {
		err = xen_pcibk_config_add_field(dev, &field[i]);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,6 +64,8 @@
 	void *data;
 };
 
+extern bool permissive;
+
 #define OFFSET(cfg_entry) ((cfg_entry)->base_offset+(cfg_entry)->field->offset)
 
 /* Add fields to a device - the add_fields macro expects to get a pointer to
```
