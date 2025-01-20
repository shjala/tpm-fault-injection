
#!/bin/bash

CWD=$(pwd)
SWTPM=/usr/local/bin/swtpm
TPM_STATE=/tmp/swtpm
TPM_CTRL="$TPM_STATE/ctrl.sock"
TPM_SRV="$TPM_STATE/srv.sock"
TPM_SRV_FAULT="$TPM_STATE/srv.proxy.sock"


echo "[+] preparing the environment ..."
rm -rf $TPM_STATE
mkdir -p $TPM_STATE

$SWTPM socket --tpm2 \
    --flags startup-clear \
    --server type=unixio,path="$TPM_SRV" \
    --ctrl type=unixio,path="$TPM_CTRL" \
    --tpmstate dir="$TPM_STATE" \
    --log file="$TPM_STATE/swtpm.log" &

SWTPM_PID=$!

# give swtpm time to start and init the TPM
sleep 1

printf "[+] running getrandom before fault injection ...\n"
tpm2 getrandom --tcti="cmd:nc -q 0 -U $TPM_SRV" 16 --hex

./fault &
FAULT_PID=$!

printf "\n[+] running getrandom after fault injection ...\n"
tpm2 getrandom --tcti="cmd:nc -q 0 -U $TPM_SRV_FAULT" 16 --hex

# we are done
kill $SWTPM_PID
kill $FAULT_PID
