# Secrecy violation of BLEreq (peripheral compromised)

As the attack trace shows, when the BLE app on the central device sends data to a peripheral device, it first sends data to the BLE stack.
The insure BLE stack that uses reactive authentication encrypts messages only if receiving error messages.
So it first directly sends the data in plaintext over-the-air to the peripheral device.
As a consequence, the attacker can obtain `BLEreq` in plaintext.
```
BLEapp ---(BLEreq)--> BLE_insecure_stack ---(BLEreq)--> Attacker
```

Since the request in plaintext, the attacker can intercept this packet and respond with a fake response in plaintext.

This attack trace corresponds to the BLESA attack [6] (WOOT'2020).