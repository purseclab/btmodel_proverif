# Authentication violation of the provisioner (no OOB public key exchange and output OOB authentication)

As the attack trace shows, the attacker first acts as MitM.
When the provisioning protocol starts, the provisioner sends out provisioning invitation and receives provisioning capabilities from the device.

```
Provisioner --(~M)--> Attacker --(a_1)--> Device
Provisioner <-(a)---- Attacker <-(~M_1)-- Device
```

Then, the provisioner sends provisioning start to the device followed by the provisioner's public key.
After that, it receives the device's public key.
During the communication, the attacker can replace the provisioner's/device's public key (~M_3 and ~M_4) with her public key (a_4 and a_2).

```
Provisioner --(~M_2)-->   Attacker   --(a_3)--> Device
Provisioner --(~M_3)-->   Attacker   --(a_4)--> Device
Provisioner <--(a_2)---   Attacker   <-(~M_4)-- Device
```

Then, the device shows a number to the user and the user inputs this number into the provisioner.

```
Device --(auth_val_3)--> User --(auth_val_3)--> Provisioner
```

Finally, the provisioner and the device exchange a commit (confirmation value) and a random number used to calculate this commit.
The attacker can replay what is received from the provisioner to the provisioner to bypass its authentication (`recv_prov(p256(a_2,exp_P_1))`) due to a design flaw.

```
Provisioner --(~M_5)--> Attacker
            <-(~M_5)---
            --(~M_6)-->
            <-(~M_6)---
```

This violation corresponds to the BlueMAN attack (CVE-2020-26560).