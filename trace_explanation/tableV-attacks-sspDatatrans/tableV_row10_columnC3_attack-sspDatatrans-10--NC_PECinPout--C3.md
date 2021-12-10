# Secrecy violation of BCreq (Passkey Entry and Numeric Comparison)

The first part of the attack trace is similar to `tableV_row10_columnA1_attack-sspDatatrans-10--NC_PECinPout--A1`.

The attacker can follow the same procedure to finish pairing with the central device.

The last part of the attack trace is similar to the last part of the attack trace in `tableV_row01_columnC3_attack-sspDatatrans-01--JW--C3`.

The attacker can follow the same procedure to derive the session key and session nonce, and to get `BCreq` in plaintext.

This attack trace corresponds to the BThack (CVE-2020-10134) attack.