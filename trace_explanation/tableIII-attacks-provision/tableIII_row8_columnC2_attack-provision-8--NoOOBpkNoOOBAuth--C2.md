# Secrecy violation of the keys (no OOB public key exchange and no OOB authentication)

The first part of the trace is `tableIII_row8_columnA4_attack-provision-8--NoOOBpkNoOOBAuth--A4`.

The attacker can follow the same procedure to pass the confirmation value check of the device.

The attacker has all the values used to derive the session key:
`AES_CMAC(AES_CMAC(AES_CMAC(ZERO,concat(concat(AES_CMAC(ZERO,concat(concat(concat(concat(~M,~M_1),a_1),gen),~M_2)),a_2),rand_dev_2)),~M_2),prsk))` where `ZERO` and `prsk` are constant values defined in the specification

and session nonce:
`AES_CMAC(AES_CMAC(AES_CMAC(ZERO,concat(concat(AES_CMAC(ZERO,concat(concat(concat(concat(~M,~M_1),a_1),gen),~M_2)),a_2),rand_dev_2)),~M_2),prsn))` where `ZERO` and `prsn` are constant values defined in the specification.

So the attacker can send a fake `keys` packet and encrypt it using the session key and session nonce.
The device receives the fake `keys` and responds with `p_complete` encrypted using the same session key and session nonce.
```
Attacker --(~X_2)--> Device
         <-(~M_7)---
```

The attacker can receive the encrypted `p_complete` (`~M_7`) and decrypt it to obtain the plaintext.

This violation corresponds to the MitM attack.