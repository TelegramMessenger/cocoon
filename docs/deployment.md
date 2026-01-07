# Deployment and Testing

## Prerequisites

- Linux server (Kernel 6.16+ for full TDX support) with:
  - Intel TDX-capable CPU
  - NVIDIA GPU with CC support (H100+) (for actual workers)
  - QEMU with TDX support (10.1+)

**Enable TDX and GPU:**

First you should enable TDX and prepare the GPU for confidential computing. For this you may refer to:

- [Enabling Intel TDX](https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/03/hardware_selection/) - Probably you will have to enable TDX in BIOS. It could be problematic on machines from cloud providers.
- [Enabling CC on NVIDIA GPU](https://github.com/NVIDIA/gpu-admin-tools) - You may have to update your VBIOS for GPU attestation to fully work. Note that it could be complicated as you can't simply download it and would have to contact support

One straightforward way to prepare your hardware is to use the [canonical guide](https://github.com/canonical/tdx), but it could be too specific for general use.

**Verify TDX on host:**
```bash
# Check TDX support in kernel messages
dmesg | grep -i tdx

# Should see messages about TDX initialization
```

**Setup GPU:**
- Use [`scripts/setup-gpu-vfio`](../scripts/setup-gpu-vfio) to configure GPU for passthrough

## Quick Start

If you want just to run a worker, please see [readme](../README.md). The following instructions are mostly for developers.

## Building from Source

```bash
git clone --recursive https://github.com/TelegramMessenger/cocoon.git
cd cocoon
```

`cocoon-launch` will automatically initialize CMake and build the necessary binaries on the first run. It uses the `build/` directory by default.

```bash
./scripts/cocoon-launch --build-dir <path> --just-build 
```

**Manual build:**  
Install Dependencies:  
```bash
sudo apt install libjemalloc-dev liblz4-dev # Debian, Ubuntu
sudo dnf install jemalloc-devel lz4-devel # Fedora, CentOS
sudo pacman -S jemalloc lz4 # Arch Linux
```  
Build:  
```bash
mkdir build && cd build
cmake -GNinja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_SHARED_LIBS=OFF \
  -DTON_USE_JEMALLOC=ON \
  -DTON_USE_ABSEIL=OFF \
  -DTON_ONLY_TONLIB=ON \
  -DTON_USE_ROCKSDB=ON \
  ..
cmake --build . -j$(nproc)
```

## Building Models

Models are built separately and verified with dm-verity (see [Model Validation](gpu.md#model-validation)).

```bash
# Build model (downloads, creates tar + verity)
./scripts/build-model Qwen/Qwen3-0.6B

# Generates files: 
# - images/Qwen_Qwen3_0_6B.tar
# - images/Qwen_Qwen3_0_6B.verity
# - images/Qwen_Qwen3_0_6B.hash

# Output:
# <model_name>:<model_commit>:<verity_hash> <tar_path>
```

cocoon-launch auto-builds models if needed when `--model` is specified.

## Use Case 1: Local Test + Benchmark

Run all components locally without VM or TON for fast iteration and debugging.

```bash
# Start all components (auto-builds on first run)
./scripts/cocoon-launch --local-all

# In another terminal: run benchmarks
cd benchmark
./run-benchmark.sh -c 1 -n 10
./run-benchmark.sh -c 2 -n 10
```

Runs locally with fake-TON. Benchmark tests network/protocol layer, not AI inference. 
But if you want, you may use actual inference server instead of fake HTTP one which is started by ./run-benchmark.sh

## Use Case 2: Test Images with Fake-TON

Run proxy and worker in TDX VMs with fake TON blockchain.

### Build Test Image

```bash
# Build image (one-time, takes ~10-30 minutes)
./scripts/build-image test
# Outputs to images/test/
```

This is a heavy operation: it builds a complete Debian-based TDX image with mkosi. Only needed once (or when the image changes).

### Start Components

```bash
# Terminal 1: Start proxy (in TDX VM)
./scripts/cocoon-launch --test --fake-ton scripts/proxy.conf

# Terminal 2: Start worker (in TDX VM, with GPU)
export HF_TOKEN=hf_...  # For model download
./scripts/cocoon-launch --test --fake-ton --gpu 0000:01:00.0 scripts/worker.conf

# Terminal 3: Start client (optional)
./scripts/cocoon-launch --test --fake-ton scripts/client.conf
```

Configs in `scripts/` work out of the box. GPU and HF token specified via command-line flags.

Test version doesn't check image hashes. And it allows access to VM via SSH (11005 for proxy, 12005 for worker, root password: 12345)

### Verify

```bash
# Check worker stats (JSON)
curl http://localhost:12000/jsonstats

# Check worker is running
curl http://localhost:12000/stats
```

Proxy and worker run in real TDX VMs with real attestation. There is no true blockchain connection at this point - payments are simulated. Note that in this mode we don't actually verify the TDX image hash. As such, this mode should not be used in any publicly accessible configuration.

Also, the VM allows SSH on ports 12005 and 11005, and the disk is encrypted with a constant key.

## Use Case 3: Test Images with Real TON

Without --fake-ton, real TON will be used.

What you need for a start is a TON config with reliable list of liteservers. You should put this file in spec/mainnet-full-ton-config.json. Pass it via --ton-config <path> to cocoon-launch.

You may want to create your own root smart contract for testing purposes. If you use --test options, TDX hashes will not be checked for convenience, so most important part of root contract will be proxy addresses (something like `127.0.0.1:11001 127.0.0.1:11002`), it is addresses to which worker and client will connect. For details see [smart-contracts repo](https://github.com/TelegramMessenger/cocoon-contracts)

Note that you don't have to manually create proxy, worker and client's smart contracts. It is all handled automatically.

**NB**: testnet is currently not supported, minor changes in spec are required.

You will have to put some TONs on worker, client and proxy accounts. See their HTTP stats for details.

## Use Case 4: Production Deployment

Simply use `./cocoon-launch`. It is better to call it from downloaded archive, so we won't have to rebuild everything.

With production deployment you will also have to run seal-server:
```bash
./seal-server --enclave-path enclave.so
```

Note that `enclave.so` must be taken from archive (i.e. it must be exactly the same).
It is needed for sealing key in TDX guest. Guest will communicate with `seal-server` to generate machine specific key known only to guest itself.
Without seal-server, cocoon-init will fail and VM won't start.

Apart from that it is mostly like test deployment. Only now you won't have access via SSH to the guest. And hashes will be verified by parties.

## Health Monitoring

### HTTP Stats

HTTP stats are available on the following ports:
- Port 10000 for client
- Port 11000 for proxy
- Port 12000 for worker

For instances, add (instance * 10) to the port number.

**Available endpoints:**
- `/stats` - Human-readable statistics of the runner
- `/jsonstats` - JSON-formatted statistics
- `/perf` - Current performance stats of the runner

**Examples:**
```bash
# Worker instance 0
curl http://localhost:12000/stats
curl http://localhost:12000/jsonstats

# Worker instance 1
curl http://localhost:12010/stats
```

### Health Client

`health-client` queries guest VM service status and logs from the host using vsock (no network exposure). This provides deeper insights than HTTP stats.

**Basic Usage:**

```bash
# Using instance names (recommended)
./health-client --instance worker <command> [args]
./health-client -i worker:3 <command> [args]

# Using CID directly
./health-client --cid 6 <command> [args]
```

**Available Commands:**

| Command | Description | Example |
|---------|-------------|---------|
| `status [service]` | Overall health and service status | `./health-client -i worker status` |
| `sys` | System metrics (CPU, memory, disk, network) | `./health-client -i worker sys` |
| `svc <service>` | Detailed service info with recent logs | `./health-client -i worker svc cocoon-vllm` |
| `logs <service> [lines]` | Service logs (default: 100 lines) | `./health-client -i worker logs cocoon-vllm 200` |
| `tdx` | TDX attestation status (image hash + RTMRs) | `./health-client -i worker tdx` |
| `gpu` | GPU metrics (utilization, memory, temp, power) | `./health-client -i worker gpu` |
| `all` | All metrics in one view | `./health-client -i worker all` |

**Instance Types:**

| Type | Short | CID Pattern | Description |
|------|-------|-------------|-------------|
| `worker` | `w` | 6, 16, 26, ... | Worker instances |
| `proxy` | `p` | 7, 17, 27, ... | Proxy instances |
| `client` | `c` | 4, 14, 24, ... | Client instances |

CID = instance number * 10 + base CID (6 for worker, 7 for proxy, 4 for client)

**Monitored Services:**

- `cocoon-worker-runner` - Main worker service
- `cocoon-proxy-runner` - Main proxy service
- `cocoon-vllm` - vLLM inference engine
- `nvidia-tdx` - GPU attestation service

**Common Examples:**

```bash
# Check overall worker health
./health-client --instance worker status

# Check specific service status
./health-client --instance worker status cocoon-vllm

# View system metrics
./health-client -i worker sys

# View GPU metrics
./health-client -i worker gpu

# View TDX attestation info (image hash and RTMRs)
./health-client -i worker tdx

# Get detailed service info with logs
./health-client -i worker svc cocoon-vllm

# View service logs (last 100 lines)
./health-client -i worker logs cocoon-worker-runner 100

# View vLLM logs (last 200 lines)
./health-client -i worker logs cocoon-vllm 200

# Get all metrics at once
./health-client -i worker all

# Check specific instance (instance 2)
./health-client -i worker:2 status

# Check proxy logs
./health-client -i proxy logs cocoon-proxy-runner 50

# Using CID directly (worker instance 1, CID = 16)
./health-client --cid 16 sys
./health-client --cid 16 gpu
```

- For TDX details: [TDX and Images](tdx-and-images.md)
- For RA-TLS: [RA-TLS](ra-tls.md)
- For GPU setup: [GPU](gpu.md)
