# Authentication violation of the central device (Passkey Entry and Numeric Comparison)

When both Passkey Entry (PE, the central device displays a number and the peripheral device inputs this number) and Numeric Comparison (NC) are enabled by both the central and peripheral devices, the attacker can bypass the authentication on the central device.

As the attack trace shows, the attacker first impersonates the peripheral device to exchange her public key (`gen`) with the central device using NC mode.
```
Central --(~M)--> Attacker
        <-(gen)--
```

After that, the central device exchanges a commit value and random number with the attacker.
```
Central <-(HMAC_SHA256(a,concat(concat(gen,~M),zero)))-- Attacker
        -----------------------(~M_1)------------------>
        <------------------------(a)--------------------
```
Then the central device shows a number on the screen to the user.
```
Central -(SHA256(concat(concat(concat(p256(gen,exp_C_1),gen),~M_1),a))) -> User
```
However, the user may think the central device is using the PE mode in which the central device displays a number and the user inputs this number on the peripheral device.
```
Central --(ra_6)--> User
```
Consequently, the user may confirm this number.
```
Central <--(yes_confirm)--- User
```
At last, the central calculates a confirmation value and exchanges it with the attacker.
```
Central --(~M_2)--> Attacker
        <-(~X_1)---
```
The attacker knows all values used to calculate the confirmation value, so that the attacker can bypass the authentication on the central device side (`{84}event recv_central(p256(gen,exp_C_1))` in process `step3c`).

This attack trace corresponds to the BThack (CVE-2020-10134) attack.
Combined with the attack trace in `tableII_row9_columnA2_attack-ssp-09--NC_PECoutPin--A2`, the attacker can perform MitM attacks.