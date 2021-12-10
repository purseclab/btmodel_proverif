# Secrecy violation of BCrsp (Just Works)

The first part of the attack trace is the same as `tableV_row01_columnA2_attack-sspDatatrans-01--JW--A2`.
The attacker can use the same procedure to bypass the authentication and pair with the peripheral device.

After pairing, the attacker has all the values used to derive the link key `LK=HMAC_SHA256(p256(gen,exp_P_1),concat(concat(concat(concat(a,nb_6),btlk),addr_A),addr_B))` where `btlk` is a constant value defined in the specification.

Then, during data transmission, the attacker and the peripheral device first perform a challenge-response two-way authentication.
The attacker exchanges a random number (challenge) and a commit value (response), which are used to derive session key and session nonce, with the peripheral device.

```
Attacker ---(a_1)--> Peripheral
         <-(~M_7)---
         --(~X_2)-->
         <-(~M_8)---
```

The session key can be derived as `HMAC_SHA256(LK,concat(concat(concat(btak,addr_A),addr_B),last64bit(HMAC_SHA256(HMAC_SHA256(LK,concat(concat(btak,addr_A),addr_B)),concat(a_1,~M_7)))))` where `btak` is a constant value defined in the specification.

The session nonce can be derived as `last64bit(HMAC_SHA256(HMAC_SHA256(LK,concat(concat(btak,addr_A),addr_B)),concat(a_1,~M_7)))`.

With the session key and session nonce, the attacker can send a encrypted request message to the peripheral.
The peripheral's stack decrypts this message and passes it to the peripheral's app.
The app sends `BCrsp` to the peripheral's stack, and the stack then encrypts `BCrsp` and sends to the attacker.
```
Attacker ---(~X_3)--> BC_stack_peripheral  --(a_2)----> BCapp_peripheral
Attacker <--(~M_9)--- BC_stack_peripheral  <-(BCrsp)--- BCapp_peripheral
```

Since the attacker has the session key and session nonce, she can decrypt the message (`~M_9`) and obtain `BCrsp` in plaintext.

This attack trace corresponds to MitM attack.