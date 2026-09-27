---
name: Ripar Companion
description: The Ripar device's service manual, alive. Numbered procedures beside figures of the device and a printed request plate.
colors:
  paper: "#eff2f1"
  paper-2: "#f8faf9"
  paper-3: "#e3e8e7"
  ink: "#12181b"
  ink-2: "#364146"
  ink-3: "#56626a"
  rule: "#c3cccd"
  rule-2: "#a3aeb1"
  spot: "#00685c"
  spot-hover: "#00544a"
  spot-ink: "#ffffff"
  spot-wash: "#d5ebe6"
  good: "#1b6a35"
  warn: "#875200"
  warn-wash: "#f5e7cf"
  bad: "#b0241c"
  bad-wash: "#f7dcda"
  paper-dark: "#101416"
  paper-2-dark: "#161b1e"
  ink-dark: "#e3e9ea"
  ink-3-dark: "#8e999d"
  rule-dark: "#2b3337"
  spot-dark: "#3cc9b1"
  spot-ink-dark: "#03201b"
  bad-dark: "#ff7d73"
  plate: "#ffffff"
  plate-ink: "#000000"
  body-metal: "#2b3034"
  lcd-bg: "#000000"
  lcd-accent: "#00c8aa"
  lcd-head: "#14283c"
typography:
  page-title:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, Arial, sans-serif"
    fontSize: "1.75rem"
    fontWeight: 750
    lineHeight: 1.2
    letterSpacing: "-0.01em"
  section:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.375rem"
    fontWeight: 700
    lineHeight: 1.2
  step:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 700
    lineHeight: 1.2
  body:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 400
    lineHeight: 1.5
  small:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 400
    lineHeight: 1.5
  data:
    fontFamily: "ui-monospace, SF Mono, Cascadia Mono, Consolas, monospace"
    fontSize: "0.92em"
    fontWeight: 400
    lineHeight: 1.5
  lcd:
    fontFamily: "Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.35
rounded:
  sm: "4px"
  device: "22px"
spacing:
  s1: "4px"
  s2: "8px"
  s3: "12px"
  s4: "16px"
  s5: "24px"
  s6: "32px"
  s7: "48px"
components:
  button-primary:
    backgroundColor: "{colors.spot}"
    textColor: "{colors.spot-ink}"
    rounded: "{rounded.sm}"
    padding: "0 16px"
    height: "40px"
  button-primary-hover:
    backgroundColor: "{colors.spot-hover}"
  button-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.sm}"
    height: "40px"
  button-danger-solid:
    backgroundColor: "{colors.bad}"
    textColor: "{colors.paper}"
    rounded: "{rounded.sm}"
  step-mark-active:
    backgroundColor: "{colors.spot}"
    textColor: "{colors.spot-ink}"
    size: "36px"
  qr-plate:
    backgroundColor: "{colors.plate}"
    textColor: "{colors.plate-ink}"
    rounded: "{rounded.sm}"
  lcd-review:
    backgroundColor: "{colors.lcd-bg}"
    typography: "{typography.lcd}"
---

# Ripar Companion: design system

## Overview

The companion is the Ripar device's **service manual**, alive. Each screen is a numbered procedure (Setup 1 to 5) or an
operating page, set beside **figures**: Fig. A, the request QR printed on a white plate; Fig. B, the device itself
(the EMULATOR drawn as a flat technical figure with its real 320 x 240 LCD). The contents rail is the manual's table
of contents, dot leaders running to each section's state. The mood is calm and precise: a hardware signer's
documentation, not a crypto dashboard. Operate mode: the task and the device's truth always lead.

## Colors

Restrained: cool offset paper, blue-black ink, **one spot colour**, the device LCD's own teal printed deep
(`spot`, `#00685c`; `#3cc9b1` in dark). Spot is for the active step, primary actions, current selection and focus,
never decoration. Semantic inks (`good`, `warn`, `bad`) mark verification results, device review tones and chain
state; `bad` also owns the Kill switch. Dark mode is the same manual printed negative on graphite, chosen by the
system or the header toggle. Two surfaces never change with the theme: the **QR plate** (white, black modules, for
the camera) and the **LCD** (the firmware's own `UI_*` colours on black).

## Typography

One workhorse family, the platform UI sans, in a tight fixed rem scale (15 px body, 13 px small, 18 / 22 / 28 px
headings, weights 650 to 750 for headings and controls). A monospace appears only for data: addresses, hashes, keys,
calldata, amounts in tables. Full hex values are always shown whole, in 4-character reading groups (spans plus
`<wbr>`, so a selection copies the exact string). Tabular numerals everywhere. Section numbers live inside the page
title (`5 Mandate`), never as a label above it.

## Layout

A 244 px contents rail beside a content column of at most 1040 px. Procedures are an ordered list of steps: a 36 px
step mark (dashed ghost ring = not yet, spot disc = current, ink ring with a check = done, bad ring = needs
attention) joined by a hairline. Spec tables (`dl`, label column + value column, hairline rows under a 1 px ink rule)
carry every fact. Exchanges set Fig. A and Fig. B side by side (0.78 : 1.22) from 1080 px and stack below. Under
860 px the rail becomes a full-screen contents sheet behind the header's menu button; the page keeps a 16 px gutter.
At 480 px spec tables stack and the device figure tightens so its LCD stays near 0.85 scale.

## Elevation & Depth

Flat, printed. Depth comes from hairlines (`rule`, `rule-2`) and plates (`paper-2` on `paper`), not shadows. The only
shadows are the device figure's soft drop (`0 2px 4px`, `0 14px 28px -16px`) and the LCD review panel's, so the
object reads as an object on the page. Figures carry crop marks at their corners, like printed plates.

## Shapes

4 px radius for controls, plates, inputs and marks (status marks are 2 px, stamped, outlined in their ink); the
device body is the one rounded object (22 px, 16 px on phones). Circles only for step marks and the lens.

## Components

- **Buttons**: primary (spot fill), secondary (1 px ink outline), danger (bad outline; solid for relaying a PANIC or a
  denial), quiet (text). States: hover, active (1 px press), focus ring (2 px spot, 2 px offset), disabled (45 %),
  busy (spinner replaces the icon, `aria-busy`).
- **Marks**: printed stamps in capitals (VERIFIED, REGISTERED, LIVE, KILLED BY PANIC, EMULATOR - DEMO KEYS).
- **Notes**: Note / Caution / Warning / Done, an icon and a bold word between two hairlines; no coloured side bars.
- **QR plate**: white plate, the QR at up to 320 px, one fixed cell per multipart part (black = on screen, grey =
  shown this loop), "Part n of N, 300 ms per frame".
- **Device figure**: flat graphite body, lens, SIGN pin, thumb window (red while a thumb is on, brighter on a beat),
  the LCD painted from `state().display`, an `EMULATOR` stamp; below it the SIGN key (press / hold with a 10-cell hold
  meter, 2 s and 5 s marked) and the thumb toggle with bpm.
- **LCD review panel**: "What your device will show": the firmware's review lines in the LCD's colours and header.
- **Transaction panel**: the summary, contract, explicit gas limit and courier, one send button, staged status
  (simulating, courier, pending, confirmed with gas used) and the decoded revert reason on failure.

## Do's and Don'ts

- Do show every address and hash in full, grouped; never truncate where the user decides.
- Do label every companion or agent claim as such, and every emulator artefact EMULATOR - DEMO KEYS.
- Do keep the spot colour for state and action; keep the QR plate white in both themes.
- Don't put a kicker or eyebrow above a heading; the number belongs in the title.
- Don't add glass, glows, gradients or neon: this is a printed manual and a matte device.
- Don't imitate material with bevels or gradients on the device figure; it is a flat technical drawing.
- Don't use the monospace for anything but data.
