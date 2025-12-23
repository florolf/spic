(see [compiler](/compiler/) for a hacky implementation)

# Policy

```console
$ cat testing.policy
# Policy using two sigsum test logs at test.sigsum.org/barreleye and serviceberry.tlog.stagemole.eu

log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye
log 47e481606d8acba747a6b053d6c2d191605fb122175d410a1202a91430abce39 https://serviceberry.tlog.stagemole.eu

# Test witness operated by Niels Möller running on a Glasklar Teknik server
witness poc.sigsum.org/nisse                       1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c

# Test witness operated by Rasmus Dahlberg - https://www.rgdd.se/poc-witness/about
witness rgdd.se/poc-witness                        28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806

# Test witness operated by Elias Rudberg - https://witness1.smartit.nu/witness1/about.txt
witness witness1.smartit.nu/witness1               f4855a0f46e8a3e23bb40faf260ee57ab8a18249fa402f2ca2d28a60e1a3130e

# Staging witness operated by Filippo Valsorda - https://navigli.sunlight.geomys.org/
witness witness.navigli.sunlight.geomys.org        dcbf728e02d479f5a7e20dc09adf525833ed6e797526517aeb07fc6854849fc6

# Test witness operated by Florian Larysch - https://remora.n621.de/
witness remora.n621.de                             ebcdeb78e7fdb2ef9227b2c1ef11e94600b55b4d6d9a57877e31ee89e59adc36

# Test witness operated by Mullvad VPN AB - https://witness.stagemole.eu/about
witness witness.stagemole.eu                       4a921b7caef58ae670cdc11ef4184f1c058f7b9259a9107a969f69fa54aa496f

# Test witness operated by Tillitis AB - new key since October 2025
witness tillitis.se/test-witness-1                 636582aec12f32c18a21733db9e3f718058ee7aaec6dbe4eb81781e0f4300c6e

# Test witness operated by Google TrustFabric team - https://transparency.dev/witnesses/
witness transparency.dev/DEV:witness-little-garden 2b6eb0ec483503544cde4e8fc1ce6d1921db21dffccc186865f808f7625443cc

# Group of 3 witnesses that are all run by Glasklar employees
group glasklar-test-witnesses 2 poc.sigsum.org/nisse rgdd.se/poc-witness witness1.smartit.nu/witness1

# Requiring 4 of 6 is intended to give reasonable reliability.
group quorum-rule 4 glasklar-test-witnesses witness.navigli.sunlight.geomys.org remora.n621.de witness.stagemole.eu tillitis.se/test-witness-1 transparency.dev/DEV:witness-little-garden

quorum quorum-rule
$ ./compiler.py policy testing.policy testing.policy.bin
compiling group quorum-rule
    compiling group glasklar-test-witnesses
    -> result(glasklar-test-witnesses): t=2 c=0 w(3)=['poc.sigsum.org/nisse', 'rgdd.se/poc-witness', 'witness1.smartit.nu/witness1']
-> result(quorum-rule): t=4 c=1 w(5)=['witness.navigli.sunlight.geomys.org', 'remora.n621.de', 'witness.stagemole.eu', 'tillitis.se/test-witness-1', 'transparency.dev/DEV:witness-little-garden']
$ wc -c testing.policy.bin
328 testing.policy.bin
$ hexdump -Cv testing.policy.bin
00000000  02 46 44 af 2a bd 40 f4  89 5a 00 3b ca 35 0f 9d  |.FD.*.@..Z.;.5..|
00000010  59 12 ab 30 1a 49 c7 7f  13 e5 b6 d9 05 c2 0a 5f  |Y..0.I........._|
00000020  e6 47 e4 81 60 6d 8a cb  a7 47 a6 b0 53 d6 c2 d1  |.G..`m...G..S...|
00000030  91 60 5f b1 22 17 5d 41  0a 12 02 a9 14 30 ab ce  |.`_.".]A.....0..|
00000040  39 08 1c 25 f8 a4 4c 63  54 57 e2 e3 91 d1 ef bc  |9..%..LcTW......|
00000050  a7 d4 c2 95 1a 0a ef 06  22 5a 88 1e 46 b9 89 62  |........"Z..F..b|
00000060  ac 6c 28 c9 2a 5a 3a 05  4d 31 7c 86 fc 2e eb 6a  |.l(.*Z:.M1|....j|
00000070  7a b2 05 4d 62 17 10 0d  0b e6 7d ed 5b 74 32 3c  |z..Mb.....}.[t2<|
00000080  58 06 f4 85 5a 0f 46 e8  a3 e2 3b b4 0f af 26 0e  |X...Z.F...;...&.|
00000090  e5 7a b8 a1 82 49 fa 40  2f 2c a2 d2 8a 60 e1 a3  |.z...I.@/,...`..|
000000a0  13 0e dc bf 72 8e 02 d4  79 f5 a7 e2 0d c0 9a df  |....r...y.......|
000000b0  52 58 33 ed 6e 79 75 26  51 7a eb 07 fc 68 54 84  |RX3.nyu&Qz...hT.|
000000c0  9f c6 eb cd eb 78 e7 fd  b2 ef 92 27 b2 c1 ef 11  |.....x.....'....|
000000d0  e9 46 00 b5 5b 4d 6d 9a  57 87 7e 31 ee 89 e5 9a  |.F..[Mm.W.~1....|
000000e0  dc 36 4a 92 1b 7c ae f5  8a e6 70 cd c1 1e f4 18  |.6J..|....p.....|
000000f0  4f 1c 05 8f 7b 92 59 a9  10 7a 96 9f 69 fa 54 aa  |O...{.Y..z..i.T.|
00000100  49 6f 63 65 82 ae c1 2f  32 c1 8a 21 73 3d b9 e3  |Ioce.../2..!s=..|
00000110  f7 18 05 8e e7 aa ec 6d  be 4e b8 17 81 e0 f4 30  |.......m.N.....0|
00000120  0c 6e 2b 6e b0 ec 48 35  03 54 4c de 4e 8f c1 ce  |.n+n..H5.TL.N...|
00000130  6d 19 21 db 21 df fc cc  18 68 65 f8 08 f7 62 54  |m.!.!....he...bT|
00000140  43 cc 05 0a 03 13 01 05                           |C.......|
00000148
$ ./compiler.py dump-policy testing.policy.bin
Logs:
  0: 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6
  1: 47e481606d8acba747a6b053d6c2d191605fb122175d410a1202a91430abce39

Witnesses:
  0: 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c
  1: 28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806
  2: f4855a0f46e8a3e23bb40faf260ee57ab8a18249fa402f2ca2d28a60e1a3130e
  3: dcbf728e02d479f5a7e20dc09adf525833ed6e797526517aeb07fc6854849fc6
  4: ebcdeb78e7fdb2ef9227b2c1ef11e94600b55b4d6d9a57877e31ee89e59adc36
  5: 4a921b7caef58ae670cdc11ef4184f1c058f7b9259a9107a969f69fa54aa496f
  6: 636582aec12f32c18a21733db9e3f718058ee7aaec6dbe4eb81781e0f4300c6e
  7: 2b6eb0ec483503544cde4e8fc1ce6d1921db21dffccc186865f808f7625443cc

Quorum bytecode:
  consume 3 witnesses (0 to 2), check threshold >= 2 (stack depth: 1)
  consume 5 witnesses (3 to 7), consume 1 children, check threshold >= 4 (stack depth: 1)
```

# Proof

```console
$ cat proof
version=2
log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d
leaf=0ee7c012691f61addd897dccf0756bd4aa331c0bccb7756fb070b51e2fd35eb9 23178b7acba9eead8958751c95b349f5435baeb62e2f691b9de715818d8f15d43679e83b7565e3a2ae93e6744fb41d1a1609198d6139afa2a9c461e18dc39e06

size=17157
root_hash=86c07a3959a75a8640dd01c33a62cf4222ef88ace47f706a06905d915e705a3d
signature=fb48647e55d12145b6e3169d33cd167f0c24ce6c002ce794d82edd9e055ad535d94f4f0e142792194e713561d9040e94a744a73b4afa34b6697fdd8a32a0d509
cosignature=26983895bdf491838dd4885848670562e7b728b6efa15fd9047b5b97a9a0618f 1765558886 f543a0b4cda622ae831f27460fbb103f518cc713634857ae06c7037a1bbd6bc3a34fbedf8946ecbcc95797c1e613fa0728ef35d84d9cf9b7a68a3ecccc09be04
cosignature=e4a6a1e4657d8d7a187cc0c20ed51055d88c72f340d29534939aee32d86b4021 1765558886 a1e2f429ecc987ce17a5d471f2165f6166d7c6863293c6dfa4868b7c524be3559cbb5597279e68a4cd61e56acdb6fb91e4212179693698e4519b82d1cc3e3b01
cosignature=70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc 1765558886 c568d60cc7d2bf339e4a74597adfe12e09bf9bc9c13e194774c8bc103930e5651290bffc6cb2cf57ffef18ff7d68b34d4560451a0521d6c16e595367eed8f40a
cosignature=c1d2d6935c2fb43bef395792b1f3c1dfe4072d4c6cadd05e0cc90b28d7141ed3 1765558886 0bd36c6f510e36939758d6b4df06bb90ad332ef2a590ef82a831d50876748387540891d0e4f77253b396ec57c20f07a33a2dfa644b7b44383000a62924c7e20d
cosignature=1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c 1765558886 b67271161de5010cae38a210c55e10b89ea07cb233ebba4802b34133d38de14933d81b40793a4a041bf428a632e48bd7f532f556485bc31580367df4fdae6a08
cosignature=86b5414ae57f45c2953a074640bb5bedebad023925d4dc91a31de1350b710089 1765558886 0870780996726ef5376e739f595c3e5ac1e482648f13a6c2ac215051b1c7073013470bfd5ba870338776fe9b2bd8bb41ae92fec9fae6b4715cb3c7e21b8fad03
cosignature=d960fcff859a34d677343e4789c6843e897c9ff195ea7140a6ef382566df3b65 1765558886 218b77b7825d7a982e7f5a7a678af155e3f2c1fd412fc8623f379d160a6cb65b2b575189db52cf693aa6317c3219ee327ed1c37c8df7b0311d3b267182c3a400
cosignature=49c4cd6124b7c572f3354d854d50b2a4b057a750f786cf03103c09de339c4ea3 1765558886 642aa8748405401886796c9a3dbddf57942976af469429044f7206489d4b4979c44ae445c998e0bd0b6b7e0d0da5fa7fe142338ed8a69ac521d694c3cf2cd403
cosignature=42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8 1765558886 800d6a2bc926cbc4a0a5abee357bc41b7b15d10265f17bc8421126ffae7882959d064c7ba8a921409a9a8b660341b9fdfab557638ac5827fa9ec131ca1df8308

leaf_index=17156
node_hash=4d58e1548e30cc2da6b9ebe8fd5689057ad1dc21056d1a91c43fb3c961e9aee3
node_hash=96a94198542c6f7d31edb708e2eb760935306dad212f9f0e567f075c317cab4d
node_hash=6febcd05444cbd38a488b0816bf90e75168755f3c00ceebb452c39509ee61691
node_hash=297c6cc8145fd585a9e009057191d91c9ce013957ee48ae26982ac96d52b578b
$ ./compiler.py proof testing.policy.bin proof proof.bin
Minimum cosignature set: {3, 4, 5, 6}
$ wc -c proof.bin
533 proof.bin
$ hexdump -Cv proof.bin
00000000  00 23 17 8b 7a cb a9 ee  ad 89 58 75 1c 95 b3 49  |.#..z.....Xu...I|
00000010  f5 43 5b ae b6 2e 2f 69  1b 9d e7 15 81 8d 8f 15  |.C[.../i........|
00000020  d4 36 79 e8 3b 75 65 e3  a2 ae 93 e6 74 4f b4 1d  |.6y.;ue.....tO..|
00000030  1a 16 09 19 8d 61 39 af  a2 a9 c4 61 e1 8d c3 9e  |.....a9....a....|
00000040  06 85 86 01 84 86 01 04  4d 58 e1 54 8e 30 cc 2d  |........MX.T.0.-|
00000050  a6 b9 eb e8 fd 56 89 05  7a d1 dc 21 05 6d 1a 91  |.....V..z..!.m..|
00000060  c4 3f b3 c9 61 e9 ae e3  96 a9 41 98 54 2c 6f 7d  |.?..a.....A.T,o}|
00000070  31 ed b7 08 e2 eb 76 09  35 30 6d ad 21 2f 9f 0e  |1.....v.50m.!/..|
00000080  56 7f 07 5c 31 7c ab 4d  6f eb cd 05 44 4c bd 38  |V..\1|.Mo...DL.8|
00000090  a4 88 b0 81 6b f9 0e 75  16 87 55 f3 c0 0c ee bb  |....k..u..U.....|
000000a0  45 2c 39 50 9e e6 16 91  29 7c 6c c8 14 5f d5 85  |E,9P....)|l.._..|
000000b0  a9 e0 09 05 71 91 d9 1c  9c e0 13 95 7e e4 8a e2  |....q.......~...|
000000c0  69 82 ac 96 d5 2b 57 8b  00 fb 48 64 7e 55 d1 21  |i....+W...Hd~U.!|
000000d0  45 b6 e3 16 9d 33 cd 16  7f 0c 24 ce 6c 00 2c e7  |E....3....$.l.,.|
000000e0  94 d8 2e dd 9e 05 5a d5  35 d9 4f 4f 0e 14 27 92  |......Z.5.OO..'.|
000000f0  19 4e 71 35 61 d9 04 0e  94 a7 44 a7 3b 4a fa 34  |.Nq5a.....D.;J.4|
00000100  b6 69 7f dd 8a 32 a0 d5  09 e6 94 f1 c9 06 06 a1  |.i...2..........|
00000110  e2 f4 29 ec c9 87 ce 17  a5 d4 71 f2 16 5f 61 66  |..).......q.._af|
00000120  d7 c6 86 32 93 c6 df a4  86 8b 7c 52 4b e3 55 9c  |...2......|RK.U.|
00000130  bb 55 97 27 9e 68 a4 cd  61 e5 6a cd b6 fb 91 e4  |.U.'.h..a.j.....|
00000140  21 21 79 69 36 98 e4 51  9b 82 d1 cc 3e 3b 01 00  |!!yi6..Q....>;..|
00000150  03 0b d3 6c 6f 51 0e 36  93 97 58 d6 b4 df 06 bb  |...loQ.6..X.....|
00000160  90 ad 33 2e f2 a5 90 ef  82 a8 31 d5 08 76 74 83  |..3.......1..vt.|
00000170  87 54 08 91 d0 e4 f7 72  53 b3 96 ec 57 c2 0f 07  |.T.....rS...W...|
00000180  a3 3a 2d fa 64 4b 7b 44  38 30 00 a6 29 24 c7 e2  |.:-.dK{D80..)$..|
00000190  0d 00 04 08 70 78 09 96  72 6e f5 37 6e 73 9f 59  |....px..rn.7ns.Y|
000001a0  5c 3e 5a c1 e4 82 64 8f  13 a6 c2 ac 21 50 51 b1  |\>Z...d.....!PQ.|
000001b0  c7 07 30 13 47 0b fd 5b  a8 70 33 87 76 fe 9b 2b  |..0.G..[.p3.v..+|
000001c0  d8 bb 41 ae 92 fe c9 fa  e6 b4 71 5c b3 c7 e2 1b  |..A.......q\....|
000001d0  8f ad 03 00 05 64 2a a8  74 84 05 40 18 86 79 6c  |.....d*.t..@..yl|
000001e0  9a 3d bd df 57 94 29 76  af 46 94 29 04 4f 72 06  |.=..W.)v.F.).Or.|
000001f0  48 9d 4b 49 79 c4 4a e4  45 c9 98 e0 bd 0b 6b 7e  |H.KIy.J.E.....k~|
00000200  0d 0d a5 fa 7f e1 42 33  8e d8 a6 9a c5 21 d6 94  |......B3.....!..|
00000210  c3 cf 2c d4 03                                    |..,..|
00000215
$
```
