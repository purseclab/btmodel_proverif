# Secrecy violation of BLErsq (Just Works)

The first part of the attack trace is similar to `tableV_row01_columnA2_attack-sspDatatrans-01--JW--A2`.
The attacker can use the same procedure to bypass the authentication and pair with the peripheral device.

After pairing, the attacker has all the values used to derive the link key
`LK=HMAC_SHA256(p256(gen,exp_P_1),concat(concat(concat(concat(a_2,~M_7),btlk),addr_A),addr_B))` where `btlk` is a constant value defined in the specification.

Then the attacker can derive the long term key of BLE from LK `LTK=AES_CMAC(AES_CMAC(LK,SALT),brle)` where `SALT` and `brle` are constant values defined in the specification.

The following message in the attack trace is not necessary.
```
BLE_stack_central --(~M_1, ~M_2)--> Attacker
```

After that, during data transmission, the attacker can exchange the random number (`~M_3`, `~M_4`, `a`, and `a_1`), which are used to derive the session key and session nonce, with the peripheral device.
```
Peripheral <----(a, a_1)----- Attacker
           ---(~M_3, ~M_4)-->
```

The session key can be derived as `AES_CMAC(LTK,concat(a, ~M_3))`.

The session nonce can be derived as `concat(a_1, ~M_4)`.

With the session key and session nonce, the attacker can send a encrypted request message to the peripheral.
The peripheral's stack decrypts this message and passes it to the peripheral's app.
The app sends `BLErsp` to the peripheral's stack, and the stack then encrypts `BLErsp` and sends to the attacker.
```
Attacker ---(~X_2)--> BLE_stack_peripheral  --(a_3)----> BLEapp_peripheral
Attacker <--(~M_9)--- BLE_stack_peripheral  <-(BLErsp)-- BLEapp_peripheral
```

With the session key and session nonce, the attacker can decrypt the message (`~M_9`) and obtain `BLErsp` in plaintext.

This attack trace corresponds to MitM attack.