# Running COCOON on TON Testnet

COCOON components already support TON testnet internally (`is_testnet` in every runner config,
testnet-aware address handling and tonlib initialisation). This document describes the launcher
support that makes it usable without editing spec files by hand.

Testnet is allowed only together with test mode (`--test`). The runners enforce this: the key manager
refuses `is_testnet` outside of test mode.

## 1. Get the testnet TON config

```bash
./scripts/fetch-testnet-ton-config
```

This downloads the official TON testnet global config and writes:

- `spec/testnet-base-ton-config.json` — network constants (DHT, zero state), without liteservers
- `spec/testnet-full-ton-config.json` — full config including liteservers

Override the source with `TON_TESTNET_CONFIG_URL` if you use your own liteservers.

## 2. Launch components on testnet

```bash
./scripts/cocoon-launch --test --testnet scripts/proxy.conf
./scripts/cocoon-launch --test --testnet scripts/worker.conf
./scripts/cocoon-launch --test --testnet scripts/client.conf
```

`--testnet` can also be set in the config file (`testnet = true` in the `[node]` section).

What `--testnet` changes:

| Setting | Mainnet (default) | `--testnet` |
|---|---|---|
| `is_testnet` in runner configs | `0` | `1` (via `IS_TESTNET` runtime var) |
| Base TON config | `spec/mainnet-base-ton-config.json` | `spec/testnet-base-ton-config.json` |
| Full TON config | `spec/mainnet-full-ton-config.json` | `spec/testnet-full-ton-config.json` |

Explicit `--ton-config-base` / `--ton-config` still take precedence.

## Whole network on one machine, on real testnet

`--local-all` runs proxy, worker, client and key manager locally without VMs. With `--testnet` it talks
to TON testnet instead of fake TON:

```bash
./scripts/fetch-testnet-ton-config
COCOON_LOCAL_PROXY_WALLET_KEY=<base64 key> COCOON_LOCAL_WORKER_WALLET_KEY=<base64 key> \
COCOON_LOCAL_CLIENT_WALLET_KEY=<base64 key> \
./scripts/cocoon-launch --local-all --testnet --root-contract-address <your testnet root> \
  --owner-address <owner address>
```

Without the `COCOON_LOCAL_*_WALLET_KEY` overrides the public test keys from the launcher are used; fund
whichever wallets you use with test GRAM. The proxy address registered in your root contract must
point at this machine (ports 11001/11002).

## 3. Root contract

The mainnet root contract address is the default and does not exist on testnet. Deploy your own root
contract to testnet with [cocoon-contracts](https://github.com/TelegramMessenger/cocoon-contracts)
(the root must be deployed with params struct version 4 and a key manager cell),
list your proxy addresses in it, and pass it with `--root-contract-address`.

Fund the proxy, worker and client wallets with test GRAM (see each component's HTTP stats for the
wallet addresses).

## Notes

- Test mode does not verify TEE image hashes. Never expose a test-mode deployment publicly as if it
  were production.
- Fake-TON (`--fake-ton`) and `--local-all` are unchanged.

## Test worker without a GPU

Workers forward inference to `127.0.0.1:8000`. `scripts/testnet-backend` is a small OpenAI-compatible stub
(stdlib Python: chat and text completions, streaming with usage, tool calls) so a GPU-less test worker can
complete requests and the whole client -> proxy -> worker path, including billing, can be exercised.
`--local-all` workers expect it on port 8000:

```bash
./scripts/testnet-backend --port 8000 --model Qwen/Qwen3-8B &
```
