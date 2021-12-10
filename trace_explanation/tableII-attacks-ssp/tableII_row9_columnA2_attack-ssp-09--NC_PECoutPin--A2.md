# Authentication violation of the peripheral device (Passkey Entry and Numeric Comparison)

When both Passkey Entry (PE, the central device displays a number and the peripheral device inputs this number) and Numeric Comparison (NC) are enabled by both the central and peripheral devices, the attacker can bypass the authentication on the peripheral device.

As the attack trace shows, when the central device starts pairing, it sends its public key to the peripheral device.
The attacker can intercept this packet and impersonate the peripheral device to use NC mode and exchange her public key (`a`) with the central device.
```
Central ---(~M)--> Attacker
        <---(a)---
```

Then, the attacker impersonates the central device to start the pairing using PE mode and exchange her public key (`gen`) with the peripheral device.
```
Peripheral <--(gen)-- Attacker
           --(~M_1)->
```

After that, in the pairing with the central device, the attacker sends a commit value to the central device and exchanges a random number with it.
```
Central <--(HMAC_SHA256(a_1,concat(concat(a,~M),zero)))--- Attacker
        --------------------(~M_2)----------------------->
        <-------------------(a_1)-------------------------
```
Then the central device shows a number on the screen to the user.
However, the user may think the central device is using the PE mode in which the central device displays a number and the user inputs this number on the peripheral device.
Consequently, the user may confirm this number.
```
Central -(SHA256(concat(concat(concat(p256(gen,exp_C_1),a),na_8),a_1)))--> User
Central <--------------------------(yes_confirm)-------------------------- User
```

Meanwhile, in the pairing with the peripheral device, the user may input the number displayed on the central device into the peripheral device, since the user thinks the central and peripheral devices are using PE mode.
```
Peripheral <-SHA256(concat(concat(concat(p256(gen,exp_C_1),a),na_8),a_1))-- User
```
The attacker can derive this value (`SHA256(concat(concat(concat(p256(gen,exp_C_1),a),na_8),a_1))`) during the pairing with the central device.
Then, in the pairing of the peripheral device, the attacker can calculate a commit value based on this number and exchange this commit value with the peripheral device followed by a random number.
```
Peripheral <--(~X_1)--- Attacker
           ---(~M_3)-->
           <--(a_2)----
           ---(~M_4)-->
```

At last, the attacker can calculate a confirmation value following the equation in the upper right corner in the PDF trace file and send this value to the peripheral device to pass its check.

```
Peripheral <-(~X_2)-- Attacker
```

This attack trace corresponds to the BThack (CVE-2020-10134) attack.
Combined with the attack trace in `tableII_row9_columnA1_attack-ssp-09--NC_PECoutPin--A1`, the attacker can perform MitM attacks.