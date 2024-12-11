### SWPTPM Fault Injector
This program acts as a proxy between a client and a software TPM (swtpm), enabling fault injection into TPM command responses. The primary purpose is to test and debug systems interacting with TPMs by simulating faulty responses.

```
➜  swtpm-fault-injection git:(main) go build -o fault
➜  swtpm-fault-injection git:(main) ✗ ./test.sh 
[+] preparing the environment ...
[+] running getrandom before fault injection ...
cb669208e63158d61e5e092580327db3
[+] running getrandom after fault injection ...
Proxy listening on /tmp/swtpm/srv.proxy.sock
Data from client:
00000000  80 01 00 00 00 16 00 00  01 7a 00 00 00 06 00 00   |.........z......|
00000010  01 00 00 00 00 7f                                  |......|
Original data from swtpm:
00000000  80 01 00 00 01 83 00 00  00 00 00 00 00 00 06 00   |................|
00000010  00 00 2e 00 00 01 00 32  2e 30 00 00 00 01 01 00   |.......2.0......|
00000020  00 00 00 00 00 01 02 00  00 00 a4 00 00 01 03 00   |................|
00000030  00 00 4b 00 00 01 04 00  00 07 e5 00 00 01 05 49   |..K............I|
00000040  42 4d 00 00 00 01 06 53  57 20 20 00 00 01 07 20   |BM.....SW  .... |
00000050  54 50 4d 00 00 01 08 00  00 00 00 00 00 01 09 00   |TPM.............|
00000060  00 00 00 00 00 01 0a 00  00 00 01 00 00 01 0b 20   |............... |
00000070  19 10 23 00 00 01 0c 00  16 36 36 00 00 01 0d 00   |..#......66.....|
00000080  00 04 00 00 00 01 0e 00  00 00 03 00 00 01 0f 00   |................|
00000090  00 00 07 00 00 01 10 00  00 00 03 00 00 01 11 00   |................|
000000a0  00 00 40 00 00 01 12 00  00 00 18 00 00 01 13 00   |..@.............|
000000b0  00 00 03 00 00 01 14 00  00 ff ff 00 00 01 16 00   |................|
000000c0  00 00 00 00 00 01 17 00  00 08 00 00 00 01 18 00   |................|
000000d0  00 00 06 00 00 01 19 00  00 10 00 00 00 01 1a 00   |................|
000000e0  00 00 0d 00 00 01 1b 00  00 00 06 00 00 01 1c 00   |................|
000000f0  00 01 00 00 00 01 1d 00  00 00 ff 00 00 01 1e 00   |................|
00000100  00 10 00 00 00 01 1f 00  00 10 00 00 00 01 20 00   |.............. .|
00000110  00 00 40 00 00 01 21 00  00 0a 84 00 00 01 22 00   |..@...!.......".|
00000120  00 01 94 00 00 01 23 32  2e 30 00 00 00 01 24 00   |......#2.0....$.|
00000130  00 00 00 00 00 01 25 00  00 00 a4 00 00 01 26 00   |......%.......&.|
00000140  00 00 4b 00 00 01 27 00  00 07 e5 00 00 01 28 00   |..K...'.......(.|
00000150  00 00 80 00 00 01 29 00  00 00 6e 00 00 01 2a 00   |......)...n...*.|
00000160  00 00 6e 00 00 01 2b 00  00 00 00 00 00 01 2c 00   |..n...+.......,.|
00000170  00 04 00 00 00 01 2d 00  00 00 00 00 00 01 2e 00   |......-.........|
00000180  00 04 00                                           |...|
Original Response to command 378: &{Tag:32769 Size:387 Res:0}
No fault for command 378
Data from client:
00000000  80 01 00 00 00 0c 00 00  01 7b 00 10               |.........{..|
Original data from swtpm:
00000000  80 01 00 00 00 1c 00 00  00 00 00 10 a7 f6 70 3e   |..............p>|
00000010  b7 d5 e1 a8 fc 40 60 c6  39 3a df 75               |.....@`.9:.u|
Original Response to command 379: &{Tag:32769 Size:28 Res:0}
Injecting fault for command 379
Modified data from swtpm:
00000000  80 01 00 00 00 1c 01 00  00 00 00 10 a7 f6 70 3e   |..............p>|
00000010  b7 d5 e1 a8 fc 40 60 c6  39 3a df 75               |.....@`.9:.u|
Modified Response to command 379: &{Tag:32769 Size:28 Res:16777216}
WARNING:esys:src/tss2-esys/api/Esys_GetRandom.c:277:Esys_GetRandom_Finish() Received TPM Error 
ERROR:esys:src/tss2-esys/api/Esys_GetRandom.c:95:Esys_GetRandom() Esys Finish ErrorCode (0x01000000) 
ERROR: Esys_GetRandom(0x1000000) - tpm:success
ERROR: Failed getrandom
ERROR: Unable to run getrandom
```