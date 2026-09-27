# Deploying the Ripar contracts to Monad testnet

**You run this yourself, with your own deployer key.** Nothing in this repo holds a key. Deploying costs testnet MON (about 1.9 MON at the time of writing; the gas estimate is about 9.2M).

## 1. Prerequisites

- [Foundry](https://getfoundry.sh).
- A deployer account with testnet MON, from the Monad faucet.
- The address that will own your Chainlink CRE workflow (`RIPAR_WORKFLOW_OWNER`). The sentinel only accepts close reports from that owner's workflow, and its CREATE2 address depends on it.

## 2. Check the addresses first (nothing is sent)

```bash
cd contracts
export RIPAR_WORKFLOW_OWNER=0xYourCreWorkflowOwner
forge script script/Deploy.s.sol --sig "predict()" --rpc-url https://testnet-rpc.monad.xyz
```

The registry, enforcer, relay and MockUSD addresses must match these (the firmware has them compiled in):

| Contract | Address |
|---|---|
| RiparDeviceRegistry | `0xA08a47c9d645926615CF04D69b7a048133F68c9f` |
| PulseCosignEnforcer | `0x64d61fe5438981DC803ED61250FEf024617ae7eE` |
| RiparReputationRelay | `0xE433dCA75CA6cd730b1006F51A26208B000eA9E2` |
| MockUSD | `0xB5b7eaffbF9bf68cbcC1Ce8B5850b2ea9d6f9a2a` |

If they differ, the contract sources or compiler settings changed: do not deploy, rebuild the firmware tables first.

## 3. Dry run, then deploy

```bash
forge script script/Deploy.s.sol --rpc-url https://testnet-rpc.monad.xyz                 # simulation only
forge script script/Deploy.s.sol --rpc-url https://testnet-rpc.monad.xyz --broadcast \
  --private-key $DEPLOYER_KEY                                                             # or --account <keystore>
```

- **Idempotent:** a contract whose address already has code is skipped. Anyone can deploy the same bytecode to the same address, and it behaves identically, so this is harmless.
- **Output:** `contracts/deployments/10143.json` is written. Point the companion and the agent at that file.
- **Gas:** Monad bills the gas **limit**, so keep forge's default estimate margin rather than raising it.

## 4. After deploying

- **Companion:** Connect → deployments JSON, from the file above.
- **Agent:** `agent/.env` sets `DEPLOYMENTS=../contracts/deployments/10143.json`, `RPC_URL`, `AGENT_PRIVATE_KEY` (a fresh key for the agent only), and optionally `QWEN_API_KEY`.
- **Device:** pairing picks up the compiled-in contracts automatically. The sentinel is the only address the companion supplies, and the device shows it for you to confirm.
