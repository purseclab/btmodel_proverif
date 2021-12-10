# Authentication violation of the central device (Just Works)

In Just Works pairing mode, the attacker can actively participate in the pairing process with the central device with her own public key (`gen`) impersonating the legitimate peripheral device.
In this case, the attacker can successfully pair with the central device.

As the trace shows, the central device and the attacker exchange their public keys:
```
Central ---(~M)--> Attacker
        <-(gen)---
```

Then, the central device and the attacker exchange a commit value followed by a random number:
```
Central <--(HMAC_SHA256(a,concat(concat(gen,~M),zero)))--- Attacker
        ----------------------(~M_1)--------------------->
        <----------------------(a)------------------------
```

Finally, the central device sends a confirmation value (`~M_2`) to the attacker.
Then, the attacker can send a confirmation value (`~X_1`) calculated following the equation at the upper right corner in the PDF trace file to pass the authentication check on the central device.
```
Central ---(~M_2)--> Attacker
        <--(~X_1)---
```

Combined with the attack trace in `tableII_row1_columnA2_attack-ssp-01--JW--A2`, the attacker can perform Man-in-the-Middle (MitM) attacks.