# Secrecy violation of BLEreq (Just Works)

The first part of the attack trace (except the `~M_1`, `~M_2`, `a`, and `a_1` messages, will explain later in this document) is similar to `tableV_row01_columnA1_attack-sspDatatrans-01--JW--A1`.
The attacker can use the same procedure to bypass the authentication and pair with the central device.

After pairing, the attacker has all the values used to derive the link key `LK=HMAC_SHA256(p256(gen,exp_C_1),concat(concat(concat(concat(~M_3,a_2),btlk),addr_A),addr_B))` where `btlk` is a constant value defined in the specification.

Then the attacker can derive the long term key of BLE from LK `LTK=AES_CMAC(AES_CMAC(LK,SALT),brle)` where `SALT` and `brle` are constant values defined in the specification.

After that, during data transmission, the attacker can exchange the random number (`~M_1`, `~M_2`, `a`, and `a_1`), which are used to derive session key and session nonce, with the central device.
```
Central ---(~M_1, ~M_2)--> Attacker
        <----(a, a_1)-----
```

The attacker can derive the session key as `AES_CMAC(LTK,concat(~M_1,a))`.

The attacker can also derive the session nonce as `concat(~M_2,a_1)`.

When the BLE app on the central device sends data (`BLEreq`) to the peripheral device, it sends this data to the BLE stack through a secure app-stack channel.

Then, the BLE stack encrypts this data with the session key and session nonce, and sends it to the peripheral device through the insecure over-the-air channel.
So the attack can receive the encrypted message.
```
BLEapp_central --(BLEreq)--> BLE_stack_central --(~M_5)--> Attacker
```

With the session key and session nonce, the attacker can decrypt the message (`~M_5`) and obtain `BLEreq` in plaintext.

This attack trace corresponds to MitM attack.