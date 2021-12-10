# Secrecy violation of the keys (no OOB public key exchange and static OOB authentication)

As the attack trace shows, the attacker first acts as MitM.
When the provisioning protocol starts, the provisioner sends out provisioning invitation and receives provisioning capabilities from the device.

```
Provisioner --(~M)--> Attacker --(a_1)--> Device
Provisioner <-(a)---- Attacker <-(~M_1)-- Device
```

Then, the provisioner sends provisioning start to the device followed by the provisioner's public key.
After that, it receives the device's public key.
During the communication, the attacker can impersonate the device with her public key (gen).

```
Provisioner --(~M_2)-->   Attacker
Provisioner --(~M_3)-->   Attacker
Provisioner <--(gen)---   Attacker
```

After that, the provisioner use a pre-shared secret number (`static_oobdata`) with the device to calculate a commit (`~M_4`).

Then, the provisioner and the device exchange such a commit (confirmation value) and a random number used to calculate the commit.
The attacker can replay what is received from the provisioner to the provisioner to bypass its authentication due to a design flaw.

```
Provisioner --(~M_4)--> Attacker
            <-(~M_4)---
            --(~M_5)-->
            <-(~M_5)---
```

After that, the provisioner derives the session key as
 `AES_CMAC(AES_CMAC(AES_CMAC(ZERO,concat(concat(AES_CMAC(ZERO,concat(concat(concat(concat(~M,~M_1),~M_2),~M_3),gen)),~M_5),~M_5)),~M_3),prsk)` where `ZERO` and `prsk` are constant values defined in the specification

 and the session nonce as

 `AES_CMAC(AES_CMAC(AES_CMAC(ZERO,concat(concat(AES_CMAC(ZERO,concat(concat(concat(concat(~M,~M_1),~M_2),~M_3),gen)),~M_5),~M_5)),~M_3),prsn)` where `ZERO` and `prsn` are constant values defined in the specification.

The provisioner encrypts `keys` with the session key and session nonce and sends the encrypted `keys` to the device through the insecure over-the-air channel.
So the attack can receive the encrypted message (`~M_6`).
```
Provisioner --(~M_6)--> Attacker
```

Since the attacker knows all the values used to derive the session key and session nonce, the attacker can derive the same session key and session nonce as the provisioner.

So the attacker can decrypt the message (`~M_6`) and obtain `keys` in plaintext.

This violation corresponds to the BlueMAN attack (CVE-2020-26560).