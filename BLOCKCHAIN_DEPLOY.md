# KYC Attestation Contract — Deployment Guide

## Contract details
- **Language:** ink! v5 (Wasm)
- **Network:** Taler blockchain (Substrate), `pallet_contracts`
- **Source:** `/home/dvolkov/kyc-attestation/src/lib.rs`
- **Build artifacts:** `/home/dvolkov/kyc-attestation/target/ink/`
  - `kyc_attestation.contract` (code + ABI bundle)
  - `kyc_attestation.wasm` (6.5K Wasm)
  - `kyc_attestation.json` (ABI metadata)

## Status
- [x] Contract written & compiled
- [x] Unit tests: 7/7 passing
- [ ] Deployed to testnet (needs TAL balance)
- [ ] Contract address saved to .env

## To deploy (requires ~5-10 TAL for storage deposit)

### 1. Fund the deployer account
Account: `5EZS5Lp5bdPdvcNfzaiFNjsTbtK78qWjCZVwACZFCEWVwRRp`

Get TAL from Taler team or transfer from existing account.

### 2. Deploy
```bash
cd /home/dvolkov/kyc-attestation
source $HOME/.cargo/env

# Upload code + instantiate contract
cargo contract instantiate \
  --url wss://node.dev.gsmsoft.eu/ \
  --suri "frozen lady season ride legal volume kingdom husband dilemma milk bench north" \
  --constructor new \
  --args \
  2>&1
```

### 3. Save contract address to .env
After deployment, copy the contract address and update `/home/dvolkov/taler-id/.env`:
```
BLOCKCHAIN_ENABLED=true
TALER_NODE_WS=wss://node.dev.gsmsoft.eu/
KYC_CONTRACT_ADDRESS=<ADDRESS_FROM_DEPLOY_OUTPUT>
BLOCKCHAIN_ATTESTER_SEED=frozen lady season ride legal volume kingdom husband dilemma milk bench north
KYC_CONTRACT_ABI_PATH=/home/dvolkov/kyc-attestation/target/ink/kyc_attestation.json
```

### 4. Restart server
```bash
kill $(cat /tmp/taler-id.pid)
nohup node /home/dvolkov/taler-id/dist/src/main.js > /tmp/taler-auth.log 2>&1 &
echo $! > /tmp/taler-id.pid
```

### 5. Verify on-chain
```bash
# After real KYC webhook, check:
curl http://localhost:3000/kyc/on-chain/<USER_ID>
```

## Mainnet deployment
Same process with mainnet RPC: `wss://node.taler.tirol/`

## Contract methods
- `attest_verification(hash, status, timestamp)` — called by backend on KYC GREEN
- `attest_kyb(hash, verified)` — called on KYB verification
- `revoke_verification(hash)` — called on GDPR deletion
- `get_verification(hash) → (kyc_status, kyc_timestamp, kyb_status, is_active)` — public read
