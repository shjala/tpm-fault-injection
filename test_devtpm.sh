
#!/bin/bash

echo "[+] building the program ..."
go generate && go build main.go swtpm_x86_bpfel.go
if [ $? -ne 0 ]; then
    echo "Failed to build the program"
    exit 1
fi

sudo ./main -dev "/dev/tpmrm0" \
    -comm "tpm2" \
    -inputs="CmdGetRandom:RCFailure:5s:false" > /dev/tty 2>&1 &
BG_PID=$!
echo "Fault injection process: $BG_PID"
sleep 1

printf "[+] Running tpm2_getrandom ...\n"
tpm2 getrandom 16 --hex

sleep 10

printf "[+] Running tpm2_getrandom ...\n"
tpm2 getrandom 16 --hex

echo 
echo "Press CTRL+C to terminate the fault injection process"
wait $BG_PID