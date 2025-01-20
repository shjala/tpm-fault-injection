package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	MaxFaultEntries   = 256
	ReqHeaderPresent  = 0x1
	RespHeaderPresent = 0x2
	FaultRandom       = 0x1
	FaultActive       = 0x2
	FaultDeactive     = 0x3
)

var cmdMap = map[string]tpmutil.Command{
	"CmdNVUndefineSpaceSpecial":     tpm2.CmdNVUndefineSpaceSpecial,
	"CmdEvictControl":               tpm2.CmdEvictControl,
	"CmdUndefineSpace":              tpm2.CmdUndefineSpace,
	"CmdClear":                      tpm2.CmdClear,
	"CmdHierarchyChangeAuth":        tpm2.CmdHierarchyChangeAuth,
	"CmdDefineSpace":                tpm2.CmdDefineSpace,
	"CmdCreatePrimary":              tpm2.CmdCreatePrimary,
	"CmdIncrementNVCounter":         tpm2.CmdIncrementNVCounter,
	"CmdWriteNV":                    tpm2.CmdWriteNV,
	"CmdWriteLockNV":                tpm2.CmdWriteLockNV,
	"CmdDictionaryAttackLockReset":  tpm2.CmdDictionaryAttackLockReset,
	"CmdDictionaryAttackParameters": tpm2.CmdDictionaryAttackParameters,
	"CmdPCREvent":                   tpm2.CmdPCREvent,
	"CmdPCRReset":                   tpm2.CmdPCRReset,
	"CmdSequenceComplete":           tpm2.CmdSequenceComplete,
	"CmdStartup":                    tpm2.CmdStartup,
	"CmdShutdown":                   tpm2.CmdShutdown,
	"CmdActivateCredential":         tpm2.CmdActivateCredential,
	"CmdCertify":                    tpm2.CmdCertify,
	"CmdCertifyCreation":            tpm2.CmdCertifyCreation,
	"CmdReadNV":                     tpm2.CmdReadNV,
	"CmdReadLockNV":                 tpm2.CmdReadLockNV,
	"CmdPolicySecret":               tpm2.CmdPolicySecret,
	"CmdCreate":                     tpm2.CmdCreate,
	"CmdECDHZGen":                   tpm2.CmdECDHZGen,
	"CmdImport":                     tpm2.CmdImport,
	"CmdLoad":                       tpm2.CmdLoad,
	"CmdQuote":                      tpm2.CmdQuote,
	"CmdRSADecrypt":                 tpm2.CmdRSADecrypt,
	"CmdSequenceUpdate":             tpm2.CmdSequenceUpdate,
	"CmdSign":                       tpm2.CmdSign,
	"CmdUnseal":                     tpm2.CmdUnseal,
	"CmdPolicySigned":               tpm2.CmdPolicySigned,
	"CmdContextLoad":                tpm2.CmdContextLoad,
	"CmdContextSave":                tpm2.CmdContextSave,
	"CmdECDHKeyGen":                 tpm2.CmdECDHKeyGen,
	"CmdEncryptDecrypt":             tpm2.CmdEncryptDecrypt,
	"CmdFlushContext":               tpm2.CmdFlushContext,
	"CmdLoadExternal":               tpm2.CmdLoadExternal,
	"CmdMakeCredential":             tpm2.CmdMakeCredential,
	"CmdReadPublicNV":               tpm2.CmdReadPublicNV,
	"CmdPolicyCommandCode":          tpm2.CmdPolicyCommandCode,
	"CmdPolicyOr":                   tpm2.CmdPolicyOr,
	"CmdReadPublic":                 tpm2.CmdReadPublic,
	"CmdRSAEncrypt":                 tpm2.CmdRSAEncrypt,
	"CmdStartAuthSession":           tpm2.CmdStartAuthSession,
	"CmdGetCapability":              tpm2.CmdGetCapability,
	"CmdGetRandom":                  tpm2.CmdGetRandom,
	"CmdHash":                       tpm2.CmdHash,
	"CmdPCRRead":                    tpm2.CmdPCRRead,
	"CmdPolicyPCR":                  tpm2.CmdPolicyPCR,
	"CmdReadClock":                  tpm2.CmdReadClock,
	"CmdPCRExtend":                  tpm2.CmdPCRExtend,
	"CmdEventSequenceComplete":      tpm2.CmdEventSequenceComplete,
	"CmdHashSequenceStart":          tpm2.CmdHashSequenceStart,
	"CmdPolicyGetDigest":            tpm2.CmdPolicyGetDigest,
	"CmdPolicyPassword":             tpm2.CmdPolicyPassword,
	"CmdEncryptDecrypt2":            tpm2.CmdEncryptDecrypt2,
}

var errMap = map[string]uint32{
	"RCInitialize":      uint32(tpm2.RCInitialize),
	"RCFailure":         uint32(tpm2.RCFailure),
	"RCSequence":        uint32(tpm2.RCSequence),
	"RCPrivate":         uint32(tpm2.RCPrivate),
	"RCHMAC":            uint32(tpm2.RCHMAC),
	"RCDisabled":        uint32(tpm2.RCDisabled),
	"RCExclusive":       uint32(tpm2.RCExclusive),
	"RCAuthType":        uint32(tpm2.RCAuthType),
	"RCAuthMissing":     uint32(tpm2.RCAuthMissing),
	"RCPolicy":          uint32(tpm2.RCPolicy),
	"RCPCR":             uint32(tpm2.RCPCR),
	"RCPCRChanged":      uint32(tpm2.RCPCRChanged),
	"RCUpgrade":         uint32(tpm2.RCUpgrade),
	"RCTooManyContexts": uint32(tpm2.RCTooManyContexts),
	"RCAuthUnavailable": uint32(tpm2.RCAuthUnavailable),
	"RCReboot":          uint32(tpm2.RCReboot),
	"RCUnbalanced":      uint32(tpm2.RCUnbalanced),
	"RCCommandSize":     uint32(tpm2.RCCommandSize),
	"RCCommandCode":     uint32(tpm2.RCCommandCode),
	"RCAuthSize":        uint32(tpm2.RCAuthSize),
	"RCAuthContext":     uint32(tpm2.RCAuthContext),
	"RCNVRange":         uint32(tpm2.RCNVRange),
	"RCNVSize":          uint32(tpm2.RCNVSize),
	"RCNVLocked":        uint32(tpm2.RCNVLocked),
	"RCNVAuthorization": uint32(tpm2.RCNVAuthorization),
	"RCNVUninitialized": uint32(tpm2.RCNVUninitialized),
	"RCNVSpace":         uint32(tpm2.RCNVSpace),
	"RCNVDefined":       uint32(tpm2.RCNVDefined),
	"RCBadContext":      uint32(tpm2.RCBadContext),
	"RCCPHash":          uint32(tpm2.RCCPHash),
	"RCParent":          uint32(tpm2.RCParent),
	"RCNeedsTest":       uint32(tpm2.RCNeedsTest),
	"RCNoResult":        uint32(tpm2.RCNoResult),
	"RCSensitive":       uint32(tpm2.RCSensitive),
}

type CommandSet struct {
	command   uint32
	errorCode uint32
	duration  time.Duration
	end       time.Time
	mode      uint32
}

type targetData struct {
	pid     uint32
	logMode uint32
	comm    [64]byte
	devPath [64]byte
}

func main() {
	logModeFlag := uint32(0)
	commandSets := []CommandSet{}
	targetPid := flag.Uint("pid", 0, "target pid")
	inputs := flag.String("inputs", "", `Comma-separated list of inputs. 
Each input should be in the format: command:error:time:random.
Examples:
  CmdClear:RCAsymmetric:10s:true
  CmdDefineSpace:RCHierarchy:5m:false
`)
	isSwtpm := flag.Bool("swtpm", false, "target is swtpm, pid is required, device path is ignored.")
	isLogMode := flag.Bool("log", false, "enable log mode (no fault injection)")
	libtpmsPath := flag.String("libtpms", "", "path to libtpms library")
	swtpmIoReadOffset := flag.Int64("swtpm-io-read-offset", 0, "ret offset for SWTPM_IO_Read")
	devPath := flag.String("dev", "/dev/tpmrm0", "path to TPM device")
	commPath := flag.String("comm", "", "optional comm name for target process")
	listErrCode := flag.Bool("list-error", false, "List error codes")
	listCmd := flag.Bool("list-command", false, "List command codes")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Println("To see kernel logs: cat /sys/kernel/tracing/trace_pipe")
		fmt.Println("\nExpected format: command:error:time:random")
		fmt.Println("Examples:")
		fmt.Println("  -inputs=CmdGetRandom:RCFailure:5s:false,CmdUnseal:RCFailure:5m:true")
	}
	flag.Parse()

	if *isLogMode {
		logModeFlag = 1
		fmt.Println("Log mode enabled, no fault injection.")
	}

	if *listErrCode {
		fmt.Println("Error codes:")
		for k := range errMap {
			fmt.Printf("  %s\n", k)
		}
		return
	}

	if *listCmd {
		fmt.Println("Commands:")
		for k := range cmdMap {
			fmt.Printf("  %s\n", k)
		}
		return
	}

	// Validate inputs
	if *inputs == "" {
		fmt.Fprintln(os.Stderr, "Error: No inputs provided.")
		flag.Usage()
		os.Exit(1)
	}

	// Parse and validate each input set
	for _, input := range strings.Split(*inputs, ",") {
		faultMode := uint32(FaultActive)

		parts := strings.Split(input, ":")
		if len(parts) != 4 {
			fmt.Fprintf(os.Stderr, "Invalid input format: '%s'. Expected format: command:error:time:random\n", input)
			os.Exit(1)
		}

		command := parts[0]
		errorCode := parts[1]
		timeValue := parts[2]
		randomValue := strings.ToLower(parts[3])
		tagetCmd, cmdExists := cmdMap[command]
		targetErr, errExists := errMap[errorCode]
		if !cmdExists {
			fmt.Fprintln(os.Stderr, "Invalid command: %s\n", command)
			os.Exit(1)
		}

		if !errExists {
			fmt.Fprintln(os.Stderr, "Invalid error code: %s\n", errorCode)
			os.Exit(1)
		}

		random, err := strconv.ParseBool(randomValue)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid random value '%s'. Expected 'true' or 'false'.\n", randomValue)
			os.Exit(1)
		}

		if random {
			faultMode = uint32(FaultRandom)
		}

		var duration time.Duration
		if duration, err = time.ParseDuration(timeValue); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid time format '%s': %v\n", timeValue, err)
			os.Exit(1)
		}

		commandSets = append(commandSets, CommandSet{
			command:   uint32(tagetCmd),
			errorCode: targetErr,
			duration:  duration,
			end:       time.Now().Add(duration),
			mode:      faultMode,
		})
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := swtpmObjects{}
	if err := loadSwtpmObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	// Update the faults_map with the faults to inject.
	for _, cmdSet := range commandSets {
		log.Printf("Activating fault for command: %x, Error Code: %d, Mode : %d\n", cmdSet.command, cmdSet.errorCode, cmdSet.mode)
		err = putFualtTableMap(&objs, cmdSet.command, cmdSet.errorCode, cmdSet.mode)
		if err != nil {
			log.Fatalf("Failed to update faults_map with fault: %v", err)
		}
	}

	if *isSwtpm {
		if libtpmsPath == nil || *libtpmsPath == "" {
			log.Fatalf("libtpms path is required for swtpm.")
		}

		if swtpmIoReadOffset == nil || *swtpmIoReadOffset == 0 {
			log.Fatalf("swtpm-io-read-offset is required for swtpm.")
		}

		err := updateTargetDataMap(&objs, &targetData{pid: uint32(*targetPid), logMode: logModeFlag})
		if err != nil {
			log.Fatalf("Failed to update target_data_map with PID: %v", err)
		}

		// Attach the eBPF programs to the kernel.
		ex, err := link.OpenExecutable(*libtpmsPath)
		if err != nil {
			log.Fatalf("opening executable: %s", err)
		}

		upSwtpmIoRead, err := ex.Uprobe("SWTPM_IO_Read", objs.UprobeSWTPM_IO_Read, nil)
		if err != nil {
			log.Fatalf("creating uprobe: %s", err)
		}
		defer upSwtpmIoRead.Close()

		urpSwtpmIoRead, err := ex.Uretprobe("SWTPM_IO_Read", objs.UretprobeSWTPM_IO_Read, &link.UprobeOptions{
			Offset: uint64(*swtpmIoReadOffset),
		})
		if err != nil {
			log.Fatalf("creating uretprobe: %s", err)
		}
		defer urpSwtpmIoRead.Close()

		upSwtpmIoWrite, err := ex.Uprobe("SWTPM_IO_Write", objs.UprobeSWTPM_IO_Write, nil)
		if err != nil {
			log.Fatalf("creating uprobe: %s", err)
		}
		defer upSwtpmIoWrite.Close()

		log.Printf("Targetting swtpm with PID: %d", *targetPid)
	} else {
		if devPath == nil || *devPath == "" {
			log.Fatalf("device path is required for non-swtpm.")
		}

		if len(*devPath) > 128 {
			log.Fatalf("device path is too long, max length is 128")
		}

		td := targetData{}
		td.logMode = logModeFlag
		copy(td.devPath[:], *devPath)
		if commPath != nil && *commPath != "" {
			if len(*commPath) > 128 {
				log.Fatalf("comm path is too long, max length is 128")
			}
			copy(td.comm[:], *commPath)
		}
		err := updateTargetDataMap(&objs, &td)
		if err != nil {
			log.Fatalf("Failed to update target_data_map with PID: %v", err)
		}

		kpOpenat, err := link.Kprobe("do_sys_openat2", objs.KprobeDoSysOpenat2, nil)
		if err != nil {
			log.Fatalf("creating kprobe: %s", err)
		}
		defer kpOpenat.Close()

		krOpenat, err := link.Kretprobe("do_sys_openat2", objs.KretprobeDoSysOpenat2, nil)
		if err != nil {
			log.Fatalf("creating kretprobe: %s", err)
		}
		defer krOpenat.Close()

		fxRead, err := link.AttachTracing(link.TracingOptions{
			Program:    objs.KsysRead,
			AttachType: ebpf.AttachTraceFExit,
		})
		if err != nil {
			log.Fatalf("failed to attach fexit: %s", err)
		}
		defer fxRead.Close()

		feWrite, err := link.AttachTracing(link.TracingOptions{
			Program:    objs.KsysWrite,
			AttachType: ebpf.AttachTraceFEntry,
		})
		if err != nil {
			log.Fatalf("failed to attach fentry: %s", err)
		}
		defer feWrite.Close()
	}

	// start deactivation timer
	go func() {
		for {
			for i := range len(commandSets) {
				if commandSets[i].duration > 0 {
					if time.Now().After(commandSets[i].end) {
						if commandSets[i].mode != FaultDeactive {
							err := updateFualtTableMap(&objs, commandSets[i].command, commandSets[i].errorCode, FaultDeactive)
							if err != nil {
								log.Fatalf("Failed to update faults_map with fault: %v", err)
							}
							commandSets[i].mode = FaultDeactive
							log.Printf("Deactivating, fault duration expired for command: %x, Error Code: %d, Mode : %d\n", commandSets[i].command, commandSets[i].errorCode, commandSets[i].mode)
						}
					}
				}
			}
			time.Sleep(3 * time.Second)
		}
	}()

	go func() {
		for {
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt)
			<-sig
			log.Println("Received signal, exiting program..")
			rd.Close()
		}
	}()

	log.Printf("Listening for events..")
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("failed to read from perf event: %s", err)
			continue
		}

		if rec.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", rec.LostSamples)
			continue
		}

		if logModeFlag == 1 {
			var ev swtpmEvent
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &ev); err != nil {
				log.Printf("failed to parse perf event: %s", err)
				continue
			}

			log.Printf("TPM Command: %s (%d)\n", getEventStr(ev.Cmd), ev.Cmd)
		}
	}
}

func putFualtTableMap(objs *swtpmObjects, cmd, errCode, mode uint32) error {
	key := uint32(cmd)
	val := struct {
		Cmd     uint32
		ErrCode uint32
		Type    uint32
	}{
		Cmd:     cmd,
		ErrCode: errCode,
		Type:    mode,
	}
	if err := objs.FualtTableMap.Update(key, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("Failed to update faults_map with fault: %v", err)
	}

	return nil
}

func updateFualtTableMap(objs *swtpmObjects, cmd, errCode, mode uint32) error {
	key := uint32(cmd)
	val := struct {
		Cmd     uint32
		ErrCode uint32
		Type    uint32
	}{
		Cmd:     cmd,
		ErrCode: errCode,
		Type:    mode,
	}
	if err := objs.FualtTableMap.Update(key, val, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("Failed to update faults_map with fault: %v", err)
	}

	return nil
}

func updateTargetDataMap(objs *swtpmObjects, td *targetData) error {
	key := uint32(0)
	if err := objs.TargetDataMap.Update(&key, td, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("Failed to update target_data_map : %v", err)
	}

	return nil
}

func getEventStr(command uint32) string {
	for k, v := range cmdMap {
		if uint32(v) == command {
			return k
		}
	}

	return "unknown"
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
