# Secrecy violation of Mrshrsp (no OOB public key exchange and no OOB authentication)

During provisioning, the attacker acts as MitM.
Due to the lack of authentication, the attacker can impersonate the device to finish provisioning with the provisioner.
Meanwhile, the attacker can also impersonate the provisioner to finish provisioning with the device.

```
Provisioner     ---(~M)-->       Attacker    --(a_1)-->      Device
                <---(a)---       Attacker    <-(~M_1)--
                --(~M_2)->       Attacker    --(a_2)-->
                --(~M_3)->       Attacker    --(gen)-->
                <--(gen)--       Attacker    <-(~M_4)--
                --(~M_5)->       Attacker    --(~X_2)->
                <-(~X_1)--       Attacker    <-(~M_7)--
                --(~M_6)->       Attacker    --(a_4)-->
                <--(a_3)--       Attacker    <-(~M_8)--
```

The attacker can derive the same session key and session nonce as the provisioner's session key and session nonce.
So the attacker can decrypt the encrypted `keys` to obtain plaintext.

At the same time, the attacker can also derive the same session key and session nonce as the device's session key and session nonce.
The attacker can send encrypted `keys` using the device's session key and session nonce to the device.

```
Provisioner     --(~M_9)->       Attacker    --(~X_3)->      Device
                <-(~M_9)--       Attacker    <-(~M_10)-
```

After provisioning, the attacker, the provisioner, and the device have the same set of keys.

When the central (the provisioner) mesh app (`Meshapp_central`) sends a request (`Meshreq`) to the device, it encrypts `Meshreq` with the application key and application nonce following the same procedures described in `tableVI_row5_columnC7_attack-provisionDatatrans-5--NoOOBpkOutputOOBAuth--C7.md` first.

Then the central mesh app sends the encrypted `Meshreq` to the central mesh stack through a secure channel.

The central mesh stack encrypts this message again following the procedures described in `tableVI_row5_columnC7_attack-provisionDatatrans-5--NoOOBpkOutputOOBAuth--C7.md`, and sends this encrypted message to the over-the-air channel.
```
Meshapp_central  -----(app encrypted Meshreq)--->   Mesh_stack_central  ----((~M_11, ~M_12))---> Attacker
```

The attacker can receive this encrypted message and forward this message to the peripheral (the device).

Upon receiving the message, the peripheral mesh stack decrypts this message at the network level using the network encryption key (derived from the network key, see `tableVI_row5_columnC7_attack-provisionDatatrans-5--NoOOBpkOutputOOBAuth--C7.md`).

Then then it sends the decrypted message to the peripheral mesh app through a secure channel.

The peripheral mesh app decrypts the message at the application level using the application key to obtain `Meshreq` in plaintext.
```
Meshapp_peripheral  <-(app encrypted Meshreq)--- Mesh_stack_peripheral <-((~M_11, ~M_12))--- Attacker
```

The peripheral mesh app responds the `Meshreq` with `Meshrsp`.

So it first encrypts `Meshrsp` with the applications key and sends the encrypted message to the peripheral mesh stack through a secure channel.

The peripheral mesh stack encrypts the message again using the network encryption key and sends it to the central through the over-the-air channel.

So the attacker can receive the encrypted message.
```
Meshapp_Periphearl  --(app encrypted Meshrsp)--> Mesh_stack_peripheral --((~M_13, ~M_14))--> Attacker
```

Since the attacker has the keys (application key and network key), she can decrypt the message (`~M_14`) and obtain `Meshrsp` in plaintext following the procedures described in `tableVI_row5_columnC7_attack-provisionDatatrans-5--NoOOBpkOutputOOBAuth--C7.md`.

This violation corresponds to the MitM attack.