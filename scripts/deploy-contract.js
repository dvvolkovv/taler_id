/**
 * deploy-contract.js
 * Deploys kyc-attestation ink! contract to Taler testnet and saves the address.
 *
 * Usage:
 *   TALER_NODE_WS=wss://node.dev.gsmsoft.eu/ \
 *   DEPLOYER_SEED="word1 word2 ..." \
 *   node scripts/deploy-contract.js
 */

const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');
const { CodePromise } = require('@polkadot/api-contract');
const fs = require('fs');
const path = require('path');

const CONTRACT_DIR = path.join(__dirname, '../kyc-attestation/target/ink');
const WS_URL = process.env.TALER_NODE_WS || 'wss://node.dev.gsmsoft.eu/';
const SEED = process.env.DEPLOYER_SEED || '//Alice';

async function main() {
  console.log('Connecting to', WS_URL);
  const provider = new WsProvider(WS_URL);
  const api = await ApiPromise.create({ provider });

  const chain = await api.rpc.system.chain();
  console.log('Chain:', chain.toString());

  const wasmFile = path.join(CONTRACT_DIR, 'kyc_attestation.wasm');
  const abiFile  = path.join(CONTRACT_DIR, 'kyc_attestation.json');

  if (!fs.existsSync(wasmFile) || !fs.existsSync(abiFile)) {
    console.error('Contract files not found. Run: cd kyc-attestation && cargo contract build --release');
    process.exit(1);
  }

  const abi  = JSON.parse(fs.readFileSync(abiFile, 'utf8'));
  const wasm = fs.readFileSync(wasmFile);

  const keyring = new Keyring({ type: 'sr25519' });
  const deployer = keyring.addFromMnemonic(SEED);
  console.log('Deployer:', deployer.address);

  const code = new CodePromise(api, abi, wasm);
  const gasLimit = api.registry.createType('WeightV2', {
    refTime: 20_000_000_000n,
    proofSize: 131_072n,
  });

  console.log('Deploying KYC Attestation Contract...');
  const contractAddress = await new Promise((resolve, reject) => {
    code.tx['new']({ gasLimit, storageDepositLimit: null })
      .signAndSend(deployer, ({ contract, status, dispatchError }) => {
        if (status.isInBlock || status.isFinalized) {
          if (dispatchError) {
            reject(new Error('Dispatch error: ' + dispatchError.toString()));
          } else if (contract) {
            resolve(contract.address.toString());
          }
        }
      })
      .catch(reject);
  });

  console.log('\nContract deployed at:', contractAddress);
  console.log('\nAdd to .env:');
  console.log('BLOCKCHAIN_ENABLED=true');
  console.log('KYC_CONTRACT_ADDRESS=' + contractAddress);
  console.log('BLOCKCHAIN_ATTESTER_SEED=' + SEED);

  fs.writeFileSync(path.join(__dirname, 'contract-address.txt'), contractAddress);

  await api.disconnect();
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
