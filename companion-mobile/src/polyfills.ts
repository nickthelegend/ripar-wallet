// Runtime gaps of Hermes that @ripar/protocol, viem and noble rely on. Imported first by app/_layout.tsx: module
// evaluation follows import order, and the protocol computes a constant (EMULATOR_FIRMWARE_ID) with TextEncoder at load.
//
//  - crypto.getRandomValues: react-native-get-random-values (native CSPRNG). Used for request ids, co-sign nonces,
//    mandate salts and the phone's hot key.
//  - TextDecoder with { fatal: true }: the protocol decodes CBOR text strictly (a device answer with invalid UTF-8 must
//    be refused, not repaired). Hermes ships TextEncoder; its TextDecoder may be missing or ignore `fatal`, so a strict
//    UTF-8 decoder is installed unless the native one already refuses invalid input.
import 'react-native-get-random-values';
import { installTextCodec } from './lib/utf8';

installTextCodec(globalThis as unknown as Record<string, unknown>);
