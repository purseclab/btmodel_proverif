# Authentication violation of the provisioner (OOB public key exchange and input OOB authentication)

As the attack trace shows, the attacker first acts as MitM.
When the provisioning protocol starts, the provisioner sends out provisioning invitation and receives provisioning capabilities from the device.

```
Provisioner --(~M)--> Attacker --(a_1)--> Device
Provisioner <-(a)---- Attacker <-(~M_1)-- Device
```

Then, the provisioner sends provisioning start to the device and receive the device's public key from a secure OOB channel.

```
Provisioner --(~M_2)--> Attacker --(a_2)--> Device
Provisioner <-----(p256(gen,exp_D_1))------ Device
```

After that, the provisioner sends its public which can be received by the attacker.
```
Provisioner --(~M_3)--> Attacker
```

Then, the provisioner displays a number (`auth_val_3`) and the user inputs this number on the device.
But inputting this number into the device is not a necessary step.
```
Provisioner --(auth_val_3)--> User
```

At last, the provisioner and the device exchange a commit (confirmation value) and a random number used to calculate the commit.
The attacker can replay what is received from the provisioner to the provisioner to bypass its authentication (`event recv_prov(p256(p256(gen,exp_P_1),exp_D_1))`) due to a design flaw.

```
Provisioner --(~M_4)--> Attacker
            <-(~M_4)---
            --(~M_5)-->
            <-(~M_5)---
```