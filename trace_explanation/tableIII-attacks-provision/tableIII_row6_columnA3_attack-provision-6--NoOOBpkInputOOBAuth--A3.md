# Authentication violation of the provisioner (no OOB public key exchange and input OOB authentication)

As the attack trace shows, when the provisioning protocol starts, the attacker first impersonates the device to receive the provisioning invitation from the provisioner.
Then the attacker sends provisioning capabilities to the provisioner.

```
Provisioner --(~M)--> Attacker
Provisioner <-(a)---- Attacker
```

After that, the provisioner sends provisioning start to the device followed by the provisioner's public key.
It then receives the device's public key.
Since the attacker impersonates the device, the public key received by the provisioner is the attacker's public key (`a_1`).

```
Provisioner --(~M_1)-->   Attacker
Provisioner --(~M_2)-->   Attacker
Provisioner <--(a_1)---   Attacker
```

Then, the provisioner shows a number to the user and the user inputs this number on the device.
But inputting this number on the device is not a necessary step.

```
Device --(auth_val_3)--> User
```

At last, the provisioner and the device exchange a commit (confirmation value) and a random number used to calculate the commit.
The attacker can replay what is received from the provisioner to the provisioner to bypass its authentication (`recv_prov(p256(a_1,exp_P_1))`) due to a design flaw.

```
Provisioner --(~M_3)--> Attacker
            <-(~M_3)---
            --(~M_4)-->
            <-(~M_4)---
```

This violation corresponds to the BlueMAN attack (CVE-2020-26560).