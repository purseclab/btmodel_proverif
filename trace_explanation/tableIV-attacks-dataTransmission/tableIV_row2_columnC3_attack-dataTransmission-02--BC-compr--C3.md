# Secrecy violation of BCreq (peripheral compromised)

As the attack trace shows, the central and peripheral devices share the same link key (`lk_1`) after pairing through BC (`BC_secure_pairing`).

In data transmission, the BC stack on the central and peripheral devices first perform a two-way challenge-response authentication.
During authentication, the attacker relays the packet from the central to the peripheral and from the peripheral to the central.
```
BC_central_stack ---(~M)---> Attacker ---(~M)---> BC_peripheral_stack
                 <--(~M_1)-- Attacker <--(~M_1)--
                 --(~M_2)--> Attacker --(~M_2)-->
                 <--(~M_3)-- Attacker <--(~M_3)--
```

Since the attacker only relays packets, the central and peripheral devices can successfully authenticate each other.

Then, when the BC app on the central device sends data to the peripheral, the app first sends the data to the BC stack through a secure channel.
The BC stack on the central device receives the data from the BC app, encrypts it, and sends it to the peripheral device over the air.
Since the over-the-air channel is not secure, the attacker may obtain the encrypted message and forward it to the peripheral.

```
BCapp ---(BCreq)--> BC_central_stack     ---(~M_4)--> Attacker
                    BC_peripheral_stack  <--(~M_4)--- Attacker
```

Since the peripheral device is compromised, the Bluetooth stack on the peripheral device may decrypt this message and sends it to the attacker (e.g., a malicious app on the peripheral device).

```
BC_peripheral_stack --(BCreq)--> Attacker
```

This attack trace represents that if the peripheral device has a malicious app installed (compromised), the attacker can illegally access data/service on the central device through BC.
Thus, it corresponds to the BadBluetooth attack [8] (NDSS'2019).

Due to the symmetric nature of the model, if the central device is compromised while the peripheral device is not, the secrecy of `BCrsp` will be violated with a similar attack trace.
In this case, the violation represents that if the central device has a malicious app installed, the attacker can illegally access data/service on the peripheral device through BC.
This violation corresponds to the device mis-binding attack [10] (NDSS'2014).