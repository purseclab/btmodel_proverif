# Authentication violation of the peripheral device (Just Works)

In Just Works pairing mode, the attacker can actively participate in the pairing process with the peripheral device with her own public key (`gen`) impersonating the legitimate central device.
In this case, the attacker can pass the peripheral device's authentication check successfully pair with it.

As the trace shows, when the pairing starts, the central device sends its public key to the peripheral device.
This packet can be intercepted by the attacker:
```
Central ---(~M)--> Attacker
```

Then, the attacker impersonates the central device and exchange her public key with the peripheral device:
```
Attacker ---(gen)--> Peripheral
         <--(~M_1)--
```

After that, the peripheral device and the attacker exchange a commit value followed by a random number:
```
Attacker <--(~M_2)--- Peripheral
         ----(a)---->
         <--(~M_3)---
```

Finally, the attacker can send a confirmation value (`~X_1`) calculated following the equation at the upper right corner in the PDF trace file to pass the authentication check on the peripheral device.
```
Attacker ---(~X_1)--> Peripheral
```

Combined with the attack trace in `tableII_row1_columnA1_attack-ssp-01--JW--A1`, the attacker can perform Man-in-the-Middle (MitM) attacks.