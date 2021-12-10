# Secrecy violation of BLEreq (peripheral compromised)

As the attack trace shows, the apps on the central and peripheral devices initially used BC for communication and thus paired through BC (`BC_secure_pairing`).

After pairing through BC, the central and peripheral share the same link key (`lk_1`).
Due to the Cross-Stack Key Derivation (CSKD) feature, the long term key (`AES_CMAC(AES_CMAC(lk_1,SALT),brle)` where `SALT` and `brle` are constant values defined in the specification) of BLE is derived from the link key.

For this reason, if a BLE service is available on the central device, it can be illegally accessed by the attacker through a compromised peripheral device.

To achieve this, during data transmission, the BLE stack on the central and peripheral devices first exchange two random numbers used to derive session key and session nonce.
The attacker relays the packet from the central to the peripheral and from the peripheral to the central.
```
BLE_central_stack ---(~M, ~M_1)---> Attacker ---(~M, ~M_1)---> BLE_peripheral_stack
                  <--(~M_2, ~M_3)-- Attacker <--(~M_2, ~M_3)--
```

Then, if a BLE app on the central device sends data to the peripheral, it sends the data to the BLE stack on the central device through a secure channel first.
The BLE stack encrypts the data, and sends it to the peripheral device over the air.
Since the over-the-air channel is not secure, the attacker may obtain the encrypted message and forward it to the peripheral.

```
BLEapp ---(BLEreq)--> BLE_central_stack     ---(~M_4)--> Attacker
                      BLE_peripheral_stack  <--(~M_4)--- Attacker
```

Since the peripheral device is compromised, the BLE stack on the peripheral device may decrypt this message and send it to the attacker (e.g., a malicious app on the peripheral device).

```
BLE_peripheral_stack --(BLEreq)--> Attacker
```

Due to the symmetric nature of the model, if the central device is compromised while the peripheral device is not, the secrecy of `BLErsp` will be violated with a similar attack trace.

These violations represent that, even though **BC** is the stack that initially used by a benign app, if the peripheral/central device has a malicious app installed, the attacker can illegally access the data or service on the central/peripheral device through **BLE**.

This attack trace corresponds to the Cross Stack Illegal Access (CSIA) attack.
It is similar to the co-located app attack [11] (SEC'2019) because both attacks are launched through the BLE stack.
However, in the co-located app attack, BLE is the stack initially used by the benign app.
On the contrary, in CSIA, *BC* is the stack initially used by the benign app.
Even in this case, the attacker can still attack through *BLE* because of CSKD.
The "cross-stack" nature differentiate CSIA from the co-located app attack.