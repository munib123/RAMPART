# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 977_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `977_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 822-862 of the vulnerable file.

    case MODBUS_FC_WRITE_SINGLE_REGISTER: {
        int mapping_address = address - mb_mapping->start_registers;

        if (mapping_address < 0 || mapping_address >= mb_mapping->nb_registers) {
            rsp_length = response_exception(
                ctx, &sft,
                MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS, rsp, FALSE,
                "Illegal data address 0x%0X in write_register\n",
                address);
        } else {
            int data = (req[offset + 3] << 8) + req[offset + 4];

            mb_mapping->tab_registers[mapping_address] = data;
            memcpy(rsp, req, req_length);
            rsp_length = req_length;
        }
    }
        break;
    case MODBUS_FC_WRITE_MULTIPLE_COILS: {
        int nb = (req[offset + 3] << 8) + req[offset + 4];
        int mapping_address = address - mb_mapping->start_bits;

        if (nb < 1 || MODBUS_MAX_WRITE_BITS < nb) {
            /* May be the indication has been truncated on reading because of
             * invalid address (eg. nb is 0 but the request contains values to
             * write) so it's necessary to flush. */
            rsp_length = response_exception(
                ctx, &sft, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE, rsp, TRUE,
                "Illegal number of values %d in write_bits (max %d)\n",
                nb, MODBUS_MAX_WRITE_BITS);
        } else if (mapping_address < 0 ||
                   (mapping_address + nb) > mb_mapping->nb_bits) {
            rsp_length = response_exception(
                ctx, &sft,
                MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS, rsp, FALSE,
                "Illegal data address 0x%0X in write_bits\n",
                mapping_address < 0 ? address : address + nb);
        } else {
            /* 6 = byte count */
            modbus_set_bits_from_bytes(mb_mapping->tab_bits, mapping_address, nb,
                                       &req[offset + 6]);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -839,9 +839,10 @@
         break;
     case MODBUS_FC_WRITE_MULTIPLE_COILS: {
         int nb = (req[offset + 3] << 8) + req[offset + 4];
+        int nb_bits = req[offset + 5];
         int mapping_address = address - mb_mapping->start_bits;
 
-        if (nb < 1 || MODBUS_MAX_WRITE_BITS < nb) {
+        if (nb < 1 || MODBUS_MAX_WRITE_BITS < nb || nb_bits * 8 < nb) {
             /* May be the indication has been truncated on reading because of
              * invalid address (eg. nb is 0 but the request contains values to
              * write) so it's necessary to flush. */
@@ -870,9 +871,10 @@
         break;
     case MODBUS_FC_WRITE_MULTIPLE_REGISTERS: {
         int nb = (req[offset + 3] << 8) + req[offset + 4];
+        int nb_bytes = req[offset + 5];
         int mapping_address = address - mb_mapping->start_registers;
 
-        if (nb < 1 || MODBUS_MAX_WRITE_REGISTERS < nb) {
+        if (nb < 1 || MODBUS_MAX_WRITE_REGISTERS < nb || nb_bytes * 8 < nb) {
             rsp_length = response_exception(
                 ctx, &sft, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE, rsp, TRUE,
                 "Illegal number of values %d in write_registers (max %d)\n",
```
