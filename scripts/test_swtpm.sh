
#!/bin/bash

CWD=$(pwd)
SWTPM=/usr/local/bin/swtpm
LIB_TPMS="/usr/local/lib/swtpm/libswtpm_libtpms.so.0"
TPM_STATE=/tmp/swtpm
TPM_CTRL="$TPM_STATE/ctrl.sock"
TPM_SRV="$TPM_STATE/srv.sock"

echo "[+] building the program ..."
go generate && go build main.go swtpm_x86_bpfel.go
if [ $? -ne 0 ]; then
    echo "Failed to build the program"
    exit 1
fi

echo "[+] preparing the environment ..."
rm -rf $TPM_STATE
mkdir -p $TPM_STATE

"$SWTPM" socket --tpm2 \
    --flags startup-clear \
    --server type=unixio,path="$TPM_SRV" \
    --tpmstate dir="$TPM_STATE" \
    --log file="$TPM_STATE/swtpm.log" \
    --ctrl type=unixio,path="$TPM_CTRL" &

SWTPM_PID=$!
kill -STOP $SWTPM_PID

sudo ./main -swtpm -pid $SWTPM_PID \
    -libtpms "$LIB_TPMS" \
    -swtpm-io-read-offset 227 \
    -inputs="CmdGetRandom:RCFailure:5s:false" > /dev/tty 2>&1 &
BG_PID=$!
echo "Fault injection process: $BG_PID"
sleep 1

echo "Suspended SWTPM: $SWTPM_PID, press ENTER to continue it"
read dummy
kill -CONT $SWTPM_PID

printf "[+] running tpm2_getrandom ...\n"
res=$(tpm2 getrandom --tcti="cmd:nc -q 0 -U $TPM_SRV" 16 --hex)
printf "Result: %s\n" "$res"

echo "Waiting for the fault to deactivate..."
sleep 10

printf "[+] running tpm2_getrandom ...\n"
res=$(tpm2 getrandom --tcti="cmd:nc -q 0 -U $TPM_SRV" 16 --hex)
printf "Result: %s\n" "$res"
kill $SWTPM_PID
rm -rf $TPM_STATE

echo 
echo "Press CTRL+C to terminate the fault injection process"
wait $BG_PID