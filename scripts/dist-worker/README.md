# COCOON Worker

You can run a COCOON worker to earn TON by serving AI models securely and in a verifiable manner.

## Prerequisites

- Linux server (**6.16+ for full TDX support**) with:
    - Intel TDX-capable CPU
    - NVIDIA GPU with CC support (H100+)
    - QEMU with TDX support (10.1+)

First, you should enable TDX and prepare your GPU for confidential computing. For this, you may refer to:

- [Enabling Intel TDX](https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/03/hardware_selection/)
- [Enabling CC on NVIDIA GPU](https://github.com/NVIDIA/gpu-admin-tools) - You may have to update your VBIOS for GPU attestation to fully work.

One straightforward way to prepare your hardware is to use the [Canonical guide](https://github.com/canonical/tdx), but it could be too specific for general use.

You may also find the `./scripts/setup-gpu-vfio` script helpful to prepare your GPU for confidential computing. Run it without arguments to see usage instructions.

## Quick Start

1. Download the COCOON worker distribution:
   ```bash
   wget https://ci.cocoon.org/cocoon-worker-release-latest.tar.xz 
   tar xvf cocoon-worker-release-latest.tar.xz 
   # cd release-<commit-hash>
   ```

2. Start seal-server (required for production):
   ```bash
   # In a separate terminal, run seal-server
   ./bin/seal-server --enclave-path ./bin/enclave.signed.so
   ```
   You may build your own `seal-server`, but `enclave.signed.so` MUST be from the archive.
   
   **Important:** `seal-server` must be running before starting the worker. It provides secure key derivation for the TDX guest. Leave it running in the background.

3. Create configuration:
   ```bash
   cp worker.conf.example worker.conf
   vim worker.conf  # Edit with your settings (see inline comments for details)
   ```

   All required options are documented in `worker.conf.example`. You may also pass them via command-line options to `cocoon-launch`.

4. Run worker:
   ```bash
   # Production mode (requires seal-server running)
   ./scripts/cocoon-launch worker.conf
   
   # Test mode (with debug shell, real TON)
   ./scripts/cocoon-launch --test worker.conf
   
   # Test mode (with debug shell, fake TON)
   ./scripts/cocoon-launch --test --fake-ton worker.conf
   ```

   You may override most of the config options via `cocoon-launch` options:
   ```bash
   ./scripts/cocoon-launch --instance 1 --worker-coefficient 2000 --model Qwen/Qwen3-0.6B worker.conf
   ```

## Configuration

All options are set in `worker.conf` (INI format). See `worker.conf.example` for detailed comments.

### Required Options

| Option | Description |
|--------|-------------|
| `type` | Node type (always `worker` for workers) |
| `model` | AI model to serve (e.g., `Qwen/Qwen3-0.6B`) |
| `owner_address` | Your TON wallet address (receives payments) |
| `gpu` | GPU PCI address (find with: `lspci \| grep -i nvidia`) |
| `node_wallet_key` | Private key for revenue wallet (base64, keep private!) |
| `hf_token` | Hugging Face token (get from [here](https://huggingface.co/settings/tokens)) |
| `ton_config` | Path to TON network config file (see below) |
| `root_contract_address` | COCOON root contract address on TON |

### Optional Options

| Option | Default | Description |
|--------|---------|-------------|
| `instance` | `0` | Instance number for running multiple workers |
| `worker_coefficient` | `1000` | Price coefficient (1000 = 1.0x) |
| `persistent` | `persistent-worker-{instance}.img` | Persistent disk image path |

### TON Network Configuration

The `ton_config` option must point to a JSON file containing TON network configuration with reliable liteserver endpoints.

You may use the [configuration we provide](https://cocoon.org/resources/mainnet.cocoon.global.config.json) or supply your own. 

Example:
```bash
# Use included mainnet config
ton_config = mainnet-config.json

# Or use custom config
ton_config = /path/to/custom-config.json
```

**What is root_contract_address?**

This is the address of the COCOON root smart contract on TON blockchain. It contains:
- List of allowed TDX image hashes
- List of supported model hashes
- Proxy addresses for the network
- Network-wide configuration

The correct address for the current network is included in the distribution's `worker.conf.example`.

## Running Multiple Workers

Use the `instance` option to run multiple workers on the same machine (one per GPU).

Each instance automatically gets:
- Unique ports (12000, 12010, 12020, ...)
- Unique CIDs (6, 16, 26, ...)
- Separate persistent storage

Example:
```bash
# Worker 1 on GPU 0
./scripts/cocoon-launch --instance 0 --gpu 0000:01:00.0 worker.conf &

# Worker 2 on GPU 1
./scripts/cocoon-launch --instance 1 --gpu 0000:41:00.0 worker.conf &
```

## seal-server

`seal-server` is required for production deployment. It runs on the host and provides secure key derivation for TDX guests.

**Why is it needed?**

Workers need persistent keys that:
- Survive VM reboots
- Are tied to the specific TDX image and configuration
- Cannot be accessed by the host

`seal-server` uses an SGX enclave to derive these keys based on the TDX guest's attestation.

**How to run:**

```bash
# Start seal-server (keep it running)
./seal-server --enclave-path enclave.so
```

**Important:**
- Must use the `enclave.so` file included in the distribution (exact same binary)
- Must be running before starting any workers
- One `seal-server` instance can serve multiple workers
- Without `seal-server`, workers will fail to initialize

**For test mode:**

`seal-server` is not required when using `--test --fake-ton` flags.

**Common Issues:**

In case you miss required libraries (such as `libsgx_dcap_ql.so`), refer to [Intel SGX Installation Guide](https://cc-enabling.trustedservices.intel.com/intel-sgx-sw-installation-guide-linux/02/installation_instructions/) to get it for your distro.

## Monitoring

### HTTP Stats

Access worker statistics via HTTP:

```bash
# Worker instance 0
curl http://localhost:12000/stats
curl http://localhost:12000/jsonstats  # JSON format

# Worker instance 1
curl http://localhost:12010/stats
```

Available endpoints:
- `/stats` - Human-readable statistics
- `/jsonstats` - JSON-formatted statistics
- `/perf` - Performance metrics

### health-client

For detailed monitoring, use `health-client`:

```bash
# Check worker health
./health-client --instance worker status

# View system metrics
./health-client -i worker sys

# View GPU metrics
./health-client -i worker gpu

# View service logs
./health-client -i worker logs cocoon-vllm 100

# Get all metrics
./health-client -i worker all
```

Run `./health-client --help` for complete usage information. 

