# Secrecy violation of Mrshreq (no OOB public key exchange and output OOB authentication)

The first part of the attack trace is similar to `tableVI_row5_columnC1_attack-provisionDatatrans-5--NoOOBpkOutputOOBAuth--C1`.

Following the same procedure, the attacker can get `keys` in plaintext.

The attacker may obtain the network key (`netkey`), application key (`appkey`), and `ivindex` from `keys`.

The mesh app first generates the application nonce as: `concat(concat(concat(seq1_4,addr_prov),addr_dev),ivindex))`.

The the app encrypts `Meshreq` with application key and application nonce, and sends it to the mesh stack.
```
Meshapp_central --(AES_CCM((t1,Meshreq),get_app_key(keys),concat(concat(concat(seq1_4,addr_prov),addr_dev),ivindex)))--> Mesh_stack_central
```

The stack derives the network encryption key and privacy key from `netkey`:
`enckey=first_part(mod263(concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(ZERO,ONE)),AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(ZERO,ONE)),ZERO),TWO))),AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(ZERO,ONE)),ZERO),TWO)),ZERO),THREE)))))` where `ZERO`, `SMK2`, `ONE`, `TWO`, `THREE` are constant values defined in the specification

privacy key:
`prikey=last_part(mod263(concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(ZERO,ONE)),AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(ZERO,ONE)),ZERO),TWO))),AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(ZERO,ONE)),ZERO),TWO)),ZERO),THREE)))))` where `ZERO`, `SMK2`, `ONE`, `TWO`, `THREE` are constant values defined in the specification.

Then, the stack generates a network nonce: `concat9(ttl1,seq1_4,addr_prov,ivindex)`.

After that, the stack then encrypts the message again with the network encryption key and network nonce, and sends the obfuscated network nonce (`~M_8`, using the privacy key, `prikey`) and encrypted message (`~M_9`) to the device.
Since the data is sent over an insecure channel, the attack can obtain the encrypted message.
```
Mesh_stack_central --((~M_8, ~M_9))--> Attacker
```

Since the attacker knows `netkey`, she can derive the network encryption key and privacy key from `netkey`:
`enckey=first_part(mod263(concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(ZERO,ONE)),AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(ZERO,ONE)),ZERO),TWO))),AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(ZERO,ONE)),ZERO),TWO)),ZERO),THREE)))))`

`prikey=last_part(mod263(concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(ZERO,ONE)),AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(ZERO,ONE)),ZERO),TWO))),AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(concat(AES_CMAC(AES_CMAC(AES_CMAC(ZERO,SMK2),netkey),concat(ZERO,ONE)),ZERO),TWO)),ZERO),THREE)))))`

The attacker can derive the network nonce from `~M_8` and `~M_9`:

`net_nonce=deobfuscate(~M_8,e(prikey,concat(ivindex,~M_9)))`

Then, the attacker can break the network layer encryption with `enckey` and `net_nonce`:

`plain_net_data=sdec(~M_9,enckey,net_nonce)`.

Moreover, the attacker can also derive the application nonce:

`app_nonce=concat(concat(concat(secondconcat9(net_nonce),addr_prov),addr_dev),ivindex)`.

With the `appkey` and `app_nonce`, the attacker can obtain `Meshreq` in plaintext:

`Meshreq=sdec(plain_net_data, appkey, app_nonce)`.

This violation corresponds to the BlueMAN attack (CVE-2020-26560).