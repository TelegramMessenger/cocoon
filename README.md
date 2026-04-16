# Confidential Compute Open Network (COCOON) – Decentralized AI Inference on TON

COCOON enables running AI models in trusted execution environments, while earning TON cryptocurrency for compute services.

- GPU owners earn TON by serving models
- App developers plug into low-cost, secure and verifiable AI compute
- Users enjoy AI seamlessly, with full privacy and confidentiality

This repository contains all the necessary tools and documentation to both serve and access models via COCOON.

## Quick Links

**For Workers:**
offering GPUs for computation

- **Download**: [Latest worker release](https://ci.cocoon.org/cocoon-worker-release-latest.tar.xz) – Ready-to-run TEE image and setup scripts
- **Setup Guide**: Instructions are included in the release archive ([preview here](scripts/dist-worker/README.md))

**For Developers:**
requiring secure AI compute

- **Build Instructions**: See below for reproducing worker distribution from source

## Prerequisites

Before building or running the components in this repository, ensure you have the following installed:

- **CMake** 3.16 or higher
- **Docker** (for reproducible builds and VM image creation)
- **Git** with submodule support (use `git clone --recurse-submodules`)
- **QEMU** (optional, for local VM testing)
- **Python 3** (for helper scripts)

## Reproducible Build

Anyone can verify the worker distribution by rebuilding from source. Note that this step is not needed to run your own workers.

```bash
# 1. Build the VM image (reproducible)
./scripts/build-image prod

# 2. Generate distribution
./scripts/prepare-worker-dist ../cocoon-worker-dist

# 3. Verify the TEE image matches the published release
cd ../cocoon-worker-dist
sha256sum images/prod/{OVMF.fd,image.vmlinuz,image.initrd,image.cmdline}
# Compare with the published checksums
```

The same goes for model images:

```bash
# 1. This will generate a model tar file with the full model name, which includes hash and commit.
./scripts/build-model Qwen/Qwen3-0.6B
# Compare with the published model name
```

## License

See LICENSE file.
