# Secrecy violation of the keys (no OOB public key exchange and output OOB authentication)

As the attack trace shows, the attacker first acts as MitM.
When the provisioning protocol starts, the provisioner sends out provisioning invitation and receives provisioning capabilities from the device.

```
Provisioner --(~M)--> Attacker --(a_1)--> Device
Provisioner <-(a)---- Attacker <-(~M_1)-- Device
```

Then, the provisioner sends provisioning start to the device followed by the provisioner's public key.
After that, it receives the device's public key.
During the communication, the attacker can replace the provisioner's/device's public key (~M_3 and ~M_4) with her public key (a_3 and gen).

```
Provisioner --(~M_2)-->   Attacker   --(a_2)--> Device
Provisioner --(~M_3)-->   Attacker   --(a_3)--> Device
Provisioner <--(gen)---   Attacker   <-(~M_4)-- Device
```

Then, the device shows a number to the user and the user inputs this number into the provisioner.

```
Device --(auth_val_3)--> User --(auth_val_3)--> Provisioner
```

After that, the provisioner and the device exchange a commit (confirmation value) and a random number used to calculate the commit.
The attacker can replay what is received from the provisioner to the provisioner to bypass its authentication due to a design flaw.

```
Provisioner --(~M_5)--> Attacker
            <-(~M_5)---
            --(~M_6)-->
            <-(~M_6)---
```

Then, the provisioner derives the session key as
 `AES_CMAC(AES_CMAC(AES_CMAC(ZERO,concat(concat(AES_CMAC(ZERO,concat(concat(concat(concat(~M,~M_1),~M_2),~M_3),gen)),~M_6),~M_6)),~M_3),prsk)` where `ZERO` and `prsk` are constant values defined in the specification

 and the session nonce as

 `AES_CMAC(AES_CMAC(AES_CMAC(ZERO,concat(concat(AES_CMAC(ZERO,concat(concat(concat(concat(~M,~M_1),~M_2),~M_3),gen)),~M_6),~M_6)),~M_3),prsn)` where `ZERO` and `prsn` are constant values defined in the specification.

The provisioner encrypts `keys` with the session key and session nonce and sends the encrypted `keys` to the device through the insecure over-the-air channel.
So the attack can receive the encrypted message (`~M_7`).
```
Provisioner --(~M_7)--> Attacker
```

Since the attacker knows all the values used to derive the session key and session nonce, the attacker can derive the same session key and session nonce as the provisioner.

So the attacker can decrypt the message (`~M_7`) and obtain `keys` in plaintext.

This violation corresponds to the BlueMAN attack (CVE-2020-26560).