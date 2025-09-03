
#!/bin/bash

CWD=$(pwd)
LIB_TPMS="/usr/local/lib/swtpm/libswtpm_libtpms.so.0"

go generate > /dev/null
go build main.go swtpm_x86_bpfel.go > /dev/null
if [ $? -ne 0 ]; then
    echo "Failed to build the program"
    exit 1
fi

if [ -z "$1" ]; then
    echo "Usage: $0 <PID>"
    exit 1
fi

echo "Press CTRL+C to terminate the fault injection process"
sudo ./main -swtpm -pid $1 \
    -libtpms "$LIB_TPMS" \
    -swtpm-io-read-offset 227 \
    -inputs="CmdECDHZGen:RCFailure:5m:false"