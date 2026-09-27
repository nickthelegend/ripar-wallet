// The phone's hot key: a secp256k1 key generated on the phone and kept in expo-secure-store (Android Keystore-backed).
//
// It is NOT the vault owner and holds no user funds. It does two things:
//   1. pays gas for every transaction the app relays (register the device, deploy the vault, relay a kill switch or a
//      denial, redeem a payment): the "courier";
//   2. is the delegate + only redeemer of the personal mandate, whose PulseCosignEnforcer caveat has AUTO caps of 0,
//      so it can move vault funds only with a fresh device co-sign (pulse + SIGN) for that exact payment.
// A stolen phone key can therefore burn its own gas MON, never the vault. Testnet use only: fund it with testnet MON.
import * as SecureStore from 'expo-secure-store';
import { type Hex, getAddress } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';

const KEY = 'ripar.hotkey.v1';
const OPTS: SecureStore.SecureStoreOptions = { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY };

let cache: Hex | null = null;

async function load(): Promise<Hex | null> {
  if (cache) return cache;
  const v = await SecureStore.getItemAsync(KEY, OPTS);
  if (v && /^0x[0-9a-fA-F]{64}$/.test(v)) cache = v as Hex;
  return cache;
}

/** the hot key's private key, created on first use */
export async function hotKey(): Promise<Hex> {
  const k = await load();
  if (k) return k;
  const fresh = generatePrivateKey();
  await SecureStore.setItemAsync(KEY, fresh, OPTS);
  cache = fresh;
  return fresh;
}

export async function hotKeyAddress(): Promise<`0x${string}`> {
  return getAddress(privateKeyToAccount(await hotKey()).address);
}

/** replaces the hot key (a personal mandate naming the old one stops working: sign a new one) */
export async function rotateHotKey(): Promise<`0x${string}`> {
  await SecureStore.deleteItemAsync(KEY, OPTS);
  cache = null;
  return hotKeyAddress();
}
