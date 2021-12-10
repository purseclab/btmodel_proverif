# Secrecy violation of BCrsp (Passkey Entry and Numeric Comparison)

The first part of the attack trace is similar to `tableV_row09_columnA2_attack-sspDatatrans-09--NC_PECoutPin--A2`.

The attacker can follow the same procedure to finish pairing with the peripheral device.

The last part of the attack trace is similar to the last part of the attack trace in `tableV_row01_columnC4_attack-sspDatatrans-01--JW--C4`.

The attacker can follow the same procedure to derive the session key and session nonce, and to get `BCrsp` in plaintext.

This attack trace corresponds to the BThack (CVE-2020-10134) attack.