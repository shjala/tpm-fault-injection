package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"unsafe"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	swtpmSocketPath = "/tmp/swtpm/srv.sock"       // Original swtpm socket
	proxySocketPath = "/tmp/swtpm/srv.proxy.sock" // Proxy socket for fault injection
	errOffset       = 6
)

// Faults to inject for each command
var fault = map[uint32]uint32{
	// Command - Response
	uint32(tpm2.CmdGetRandom): uint32(tpm2.RCFailure),
}

type responseHeader struct {
	Tag  uint16
	Size uint32
	Res  uint32
}

type commandHeader struct {
	Tag  uint16
	Size uint32
	Cmd  uint32
}

func hexdump(data []byte, bytesPerLine int) {
	for i := 0; i < len(data); i += bytesPerLine {
		end := i + bytesPerLine
		if end > len(data) {
			end = len(data)
		}
		fmt.Printf("%08x  ", i)
		for j := i; j < i+bytesPerLine; j++ {
			if j < len(data) {
				fmt.Printf("%02x ", data[j])
			} else {
				fmt.Print("   ")
			}
			if (j-i+1)%8 == 0 {
				fmt.Print(" ")
			}
		}
		fmt.Print(" |")
		for j := i; j < end; j++ {
			if data[j] >= 32 && data[j] <= 126 {
				fmt.Printf("%c", data[j])
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
}

func main() {
	startProxy()
}

func startProxy() {
	if err := os.RemoveAll(proxySocketPath); err != nil {
		fmt.Printf("Failed to clean up old proxy socket: %v\n", err)
		os.Exit(1)
	}

	proxyListener, err := net.Listen("unix", proxySocketPath)
	if err != nil {
		fmt.Printf("Failed to create proxy socket: %v\n", err)
		os.Exit(1)
	}
	defer proxyListener.Close()
	fmt.Printf("Proxy listening on %s\n", proxySocketPath)

	for {
		clientConn, err := proxyListener.Accept()
		if err != nil {
			fmt.Printf("Error accepting client connection: %v\n", err)
			continue
		}
		go handleConnection(clientConn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	realSwtpm, err := net.Dial("unix", swtpmSocketPath)
	if err != nil {
		fmt.Printf("Error connecting to swtpm: %v\n", err)
		return
	}
	defer realSwtpm.Close()
	proxy(realSwtpm, clientConn)
}

func proxy(realSwtpm, client net.Conn) {
	for {
		buf := make([]byte, 4096)
		n, err := client.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("Error reading data from client: %v\n", err)
			}
			return
		}

		data := buf[:n]
		fmt.Println("Data from client:")
		hexdump(data, 16)

		ch := &commandHeader{}
		chSize := int(unsafe.Sizeof(ch))
		if len(data) >= chSize {
			_, err = tpmutil.Unpack(data, ch)
			if err != nil {
				fmt.Printf("error unpacking command header: %v\n", err)
				return
			}
		}

		_, err = realSwtpm.Write(data)
		if err != nil {
			fmt.Printf("Error writing data to swtpm: %v\n", err)
			return
		}

		n, err = realSwtpm.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("error reading data from swtpm: %v\n", err)
			}
			return
		}

		data = buf[:n]
		fmt.Println("Original data from swtpm:")
		hexdump(data, 16)

		rh := &responseHeader{}
		rhSize := int(unsafe.Sizeof(rh))
		if len(data) >= rhSize {
			_, err = tpmutil.Unpack(data, rh)
			if err != nil {
				fmt.Printf("error unpacking response header: %v\n", err)
				return
			}

			fmt.Printf("Original Response to command %d: %+v\n", ch.Cmd, rh)

			// inject faults
			data = injectFaults(ch.Cmd, data)
		}

		_, err = client.Write(data)
		if err != nil {
			fmt.Printf("Error writing swtp response to client: %v\n", err)
			return
		}
	}
}

func injectFaults(command uint32, data []byte) []byte {
	if _, ok := fault[command]; ok {
		fmt.Printf("Injecting fault for command %d\n", command)
		binary.LittleEndian.PutUint32(data[errOffset:errOffset+4], fault[command])

		fmt.Println("Modified data from swtpm:")
		hexdump(data, 16)

		rh := &responseHeader{}
		_, err := tpmutil.Unpack(data, rh)
		if err != nil {
			fmt.Printf("error unpacking response header: %v\n", err)
			return nil
		}

		fmt.Printf("Modified Response to command %d: %+v\n", command, rh)
	} else {
		fmt.Printf("No fault for command %d\n", command)
	}

	return data
}
