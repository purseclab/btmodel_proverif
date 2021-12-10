# Secrecy violation of BCreq (peripheral compromised)

As the attack trace shows, the apps on the central and peripheral devices initially used BLE for communication and thus paired through BLE (`BLE_secure_pairing`).

After pairing through BLE, the central and peripheral share the same long term key (`ltk_3`).
Due to the Cross-Stack Key Derivation (CSKD) feature, the link key (`AES_CMAC(AES_CMAC(ltk_3,SALT),lebr)` where `SALT` and `lebr` are constant values defined in the specification) of BC is derived from the long term key.

For this reason, if a BC service is available on the central device, it can be illegally accessed by the attacker through a compromised peripheral device.

To achieve this, during data transmission, the BC stack on the central and peripheral devices first perform a two-way challenge-response authentication.
During authentication, the attacker relays the packet from the central to the peripheral and from the peripheral to the central.
```
BC_central_stack ---(~M)---> Attacker ---(~M)---> BC_peripheral_stack
                 <--(~M_1)-- Attacker <--(~M_1)--
                 --(~M_2)--> Attacker --(~M_2)-->
                 <--(~M_3)-- Attacker <--(~M_3)--
```

Since the attacker only relays packets, the central and peripheral devices can successfully authenticate each other.

Then, if a BC app on the central device sends data to the peripheral, the app first sends the data to the BC stack through a secure channel.
The BC stack on the central device receives the data from the BC app, encrypts it, and sends it to the peripheral device over the air.
Since the over-the-air channel is not secure, the attacker may obtain the encrypted message and forward it to the peripheral.

```
BCapp ---(BCreq)--> BC_central_stack     ---(~M_4)--> Attacker
                    BC_peripheral_stack  <--(~M_4)--- Attacker
```

Since the peripheral device is compromised, the BC stack on the peripheral device may decrypt this message and send it to the attacker (e.g., a malicious app on the peripheral device).

```
BC_peripheral_stack --(BCreq)--> Attacker
```

Due to the symmetric nature of the model, if the central device is compromised while the peripheral device is not, the secrecy of `BCrsp` will be violated with a similar attack trace.

These violations represent that, even though **BLE** is the stack that initially used by a benign app, if the peripheral/central device has a malicious app installed, the attacker can illegally access the data or service on the central/peripheral device through **BC**.

This attack trace corresponds to the Cross Stack Illegal Access (CSIA) attack.
It is similar to the BadBluetooth attack [8] (NDSS'2019) and the device mis-binding attack [10] (NDSS'2014) because all three attacks are launched through the BC stack.
However, in BadBluetooth and device mis-binding attacks , BC is the stack initially used by the benign app.
On the contrary, in CSIA, *BLE* is the stack initially used by the benign app.
Even in this case, the attacker can still attack through *BC* because of CSKD.
The "cross-stack" nature differentiate CSIA from BadBluetooth and device mis-binding attacks.