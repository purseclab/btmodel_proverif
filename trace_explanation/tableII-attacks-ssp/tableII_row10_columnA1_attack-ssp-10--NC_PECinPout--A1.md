# Authentication violation of the central device (Passkey Entry and Numeric Comparison)

When both Passkey Entry (PE, the peripheral device displays a number and the central device inputs this number) and Numeric Comparison (NC) are enabled by both the central and peripheral devices, the attacker can bypass the authentication on the central device.

This attack trace is similar to `tableII_row9_columnA2_attack-ssp-09--NC_PECoutPin--A2` but there are some differences.
In `tableII_row9_columnA2_attack-ssp-09--NC_PECoutPin--A2`, the attacker pairs with the central device using NC mode and pairs with the peripheral device using PE mode.
In this trace, the attacker pairs with the central device using PE mode and pairs with the peripheral device using NC mode.
Accordingly, the user inputs a number displayed on the peripheral device into the central device.

However, despite the differences, the attacker can use similar procedures to bypass the authentication on the central device side.

This attack trace also corresponds to the BThack (CVE-2020-10134) attack.
Combined with the attack trace in `tableII_row10_columnA2_attack-ssp-10--NC_PECinPout--A2`, the attacker can perform MitM attacks.