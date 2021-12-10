# Secrecy violation of BLEreq (peripheral compromised)

As the attack trace shows, the central and peripheral devices share the same long term key (`ltk_3`) after pairing through BLE (`BLE_secure_pairing`).

In data transmission, the BLE stack on the central and peripheral devices first exchange two random numbers used to derive session key and session nonce.
The attacker relays the packet from the central to the peripheral and from the peripheral to the central.
```
BLE_central_stack ---(~M, ~M_1)---> Attacker ---(~M, ~M_1)---> BLE_peripheral_stack
                  <--(~M_2, ~M_3)-- Attacker <--(~M_2, ~M_3)--
```

Then, when the BLE app on the central device sends data to the peripheral, it sends the data to the BLE stack on the central device through a secure channel first.
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

This violation means that if the peripheral device has a malicious app installed, the attacker can illegally access the data/service on the central device through BLE.

Due to the symmetric nature of the model, if the central device is compromised while the peripheral device is not, the secrecy of `BLErsp` will be violated with a similar attack trace.

This violation means that if the central device has a malicious app installed, the attacker can illegally access the data/service on the peripheral device through BLE.
It corresponds to the co-located app attack [11] (SEC'2019).