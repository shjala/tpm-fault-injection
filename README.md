# TPM Fault Injection

An eBPF-based fault injection tool for TPM (Trusted Platform Module) systems. This tool allows injecting specific errors into TPM command responses to test system resilience and fault tolerance.

## What it does

The tool intercepts TPM commands and responses at the kernel level using eBPF and modifies response error codes to simulate various failure scenarios. It supports two modes of operation:

**Standard TPM Mode**: Hooks into kernel syscalls (`ksys_read`, `ksys_write`, `do_sys_openat2`) to intercept TPM communication through device files like `/dev/tpmrm0`.

**SWTPM Mode**: Uses userspace probes to hook into the SWTPM library functions (`SWTPM_IO_Read`, `SWTPM_IO_Write`) for software TPM implementations.

The tool provides selective fault injection based on TPM command types such as CmdGetRandom and CmdUnseal, with configurable error codes like RCFailure. It supports time-based fault activation and deactivation, with both random and deterministic fault injection modes, includes a log-only mode for monitoring TPM commands without injection, and works with both hardware (tpm driver) and software TPM implementations.

**Tested on kernel**: 6.8.0-49-generic it might not compile on other kernels as it is not using CO-RE.
