# Product

<!-- impeccable:product-schema 1 -->

> Written by a workflow build agent without an interview channel: every fact below comes from the build brief and
> the repository (docs/PROTOCOL.md, docs/FIRMWARE.md, contracts/SPEC.md, README.md). Items marked **(inferred)** were
> not confirmed by the user.

## Platform

web

## Stack

Pinned by the build brief: Vite + React 19 + TypeScript ~5.9, viem, @metamask/smart-accounts-kit 2.0.0, qrcode,
qr-scanner, @ripar/protocol (npm workspace `@ripar/companion`). Hash router, no backend except the user-configured
agent service URL and RPC URL.

## Users

- The owner of a Ripar Wallet device (an air-gapped, camera-shaped, pulse-verified hardware signer) who lets an AI
  agent spend from a MetaMask HybridDeleGator vault on Monad under a scoped mandate.
- They use the companion on a laptop or phone next to the device: pairing it, deploying and funding the vault, issuing
  a mandate, answering the agent's escalations with a live thumb on the sensor, and pulling the kill switch.
- Hackathon judges and demo viewers who run the in-page EMULATOR instead of hardware **(inferred from the brief's
  emulator requirement and README "Monad Metropolis")**.

## Product Purpose

The companion is the **untrusted online courier** between the device, the chain and the agent. It builds requests,
shows them as animated QR codes (or feeds the emulator), reads the device's single-part response QR, verifies it with
@ripar/protocol, and relays it on-chain or to the agent. Success: every device action (pair, mandate, co-sign, deny,
revoke, panic, reopen) can be completed end to end, and the user always knows what the device will show and what the
companion is merely claiming.

## Positioning

A human thumb, measured live by an air-gapped device, sits between an AI agent and the money. The companion never
decides and never holds a key: the device parses, shows and rebuilds every digest; the companion only carries bytes.

## Operating Context

- Requests travel companion -> device as BC-UR QR codes (multipart loops at ~300 ms per frame); answers travel back as
  one single-part QR read by the laptop/phone camera.
- The courier wallet (an injected EIP-1193 wallet) only pays gas; it never owns the vault.
- Networks: Monad testnet (10143) via an RPC URL setting, or a local anvil fork of it.
- Ripar contract addresses come from a deployments JSON (contracts/deployments/<chainId>.json), never hard-coded.

## Capabilities and Constraints

- Nine screens: Connect, Device, Pair, Vault, Mandate, Inbox, Kill switch, Activity, About/Proof.
- Two device transports behind one interface: hardware (camera scan + animated QR) and EMULATOR (the real firmware in
  WASM, fed the same UR parts, answering with its QR text).
- Never ask for, store or log a seed or private key. The emulator's demo NVS (which includes its seed) lives only in
  localStorage and is always labelled EMULATOR - DEMO KEYS.
- Undecided: the agent service's HTTP contract is defined by this companion (README) until the agent package exists.

## Brand Commitments

- Name: Ripar Wallet (formerly Thenar). The device is "camera-shaped", with a 320 x 240 LCD, one SIGN key and a
  thumb pulse sensor.
- Visual identity pinned by the brief: a camera-like hardware signer, calm and precise, **not** generic crypto neon.
- The emulator is always labelled EMULATOR.

## Evidence on Hand

- The WASM emulator (firmware/emu/dist) and the device protocol vectors; no real deployments JSON yet, no real
  device photos in the companion. Do not invent balances, users, audits or partner claims.

## Product Principles

1. The device decides; the companion shows what the device will show and labels its own claims "(companion)".
2. Every irreversible step (a chain write, a relay to the agent) is explicit, with its gas limit shown.
3. Show verification, not trust: each response displays its check list (VERIFIED / UNVERIFIED / FAIL).
4. Kill switch first: revoke / panic must be reachable in two moves from anywhere.

## Accessibility & Inclusion

WCAG 2.2 AA **(inferred)**: keyboard-operable everything (including the emulator SIGN key: press and hold via
Space/Enter), visible focus, reduced-motion support for the QR animation's surrounding chrome, light and dark themes,
phone width from 375 px.
