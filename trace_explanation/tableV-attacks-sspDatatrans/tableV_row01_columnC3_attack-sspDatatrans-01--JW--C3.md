# Secrecy violation of BCreq (Just Works)

The first part of the attack trace is the same as `tableV_row01_columnA1_attack-sspDatatrans-01--JW--A1`.
The attacker can use the same procedure to bypass the authentication and pair with the central device.

After pairing, the attacker has all the values used to derive the link key `LK=HMAC_SHA256(p256(gen,exp_C_1),concat(concat(concat(concat(~M_3,a),btlk),addr_A),addr_B))` where `btlk` is a constant value defined in the specification.

Then, during data transmission, the attacker and the central device first perform a challenge-response two-way authentication.
The attacker exchanges a random number (challenge) and a commit value (response), which are used to derive session key and session nonce, with the central device.

```
Central --(~M_5)--> Attacker
        <--(a_1)---
        --(~M_6)-->
        <-(~X_2)---
```

The session key can be derived as `HMAC_SHA256(LK,concat(concat(concat(btak,addr_A),addr_B),last64bit(HMAC_SHA256(HMAC_SHA256(LK,concat(concat(btak,addr_A),addr_B)),concat(~M_5,a_1)))))` where `btak` is a constant value defined in the specification.

The session nonce can be derived as `last64bit(HMAC_SHA256(HMAC_SHA256(LK,concat(concat(btak,addr_A),addr_B)),concat(~M_5,a_1)))`.

When the BC app on the central device sends data (`BCreq`) to the peripheral device, it sends this data to the BC stack through a secure app-stack channel.
Then, the BC stack encrypts this data with the session key and session nonce, and sends it to the peripheral device through the insecure over-the-air channel.
So the attack can receive the encrypted message.
```
BCapp_central --(BCreq)--> BC_stack_central --(~M_7)--> Attacker
```

With the session key and session nonce, the attacker can decrypt the message (`~M_7`) and obtain `BCreq` in plaintext.

This attack trace corresponds to MitM attack.