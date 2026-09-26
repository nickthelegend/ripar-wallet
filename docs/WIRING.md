# Ripar Wallet v1: wiring

Source: Waveshare ESP32-S3-(Touch-)LCD-2 schematic (net list) plus the silk-screen on the headers.

## Header pinout (as printed on the board)

| Pin | P1 (next to the flash chip) | P2 (next to "Waveshare") |
|---|---|---|
| 1 | GPIO2 (camera D7) | 3V3 |
| 2 | GPIO4 (camera HREF) | GND |
| 3 | GPIO6 (camera VSYNC) | **GPIO43 / TX (free)** |
| 4 | GPIO16 (camera SCCB clock) | **GPIO44 / RX (free)** |
| 5 | GPIO17 (camera PWDN) | **GPIO47 (I2C SCL, shared with the IMU)** |
| 6 | **GPIO18 (free)** | **GPIO48 (I2C SDA, shared with the IMU)** |
| 7 | GPIO21 (camera SCCB data) | GPIO15 (camera D2) |
| 8 | GPIO8 (camera XCLK) | GPIO13 (camera D1) |
| 9 | GPIO7 (camera D6) | GPIO11 (camera D3) |
| 10 | GPIO10 (camera D5) | GPIO12 (camera D0) |
| 11 | GPIO20 (USB D+, don't use) | GPIO14 (camera D4) |
| 12 | GPIO19 (USB D−, don't use) | GPIO9 (camera PCLK) |
| 13 | GND | GND |
| 14 | 5V | VBAT |

On-board, not on the headers:

| GPIO | Use |
|---|---|
| **0** | **BOOT key = our SIGN / NEXT key** (the printed Sign_Pin presses it) |
| 1 | LCD backlight |
| 3 | IMU INT1 |
| 5 | battery ADC |
| 38 / 39 | LCD MOSI / SCLK (shared with SD) |
| 40 / 41 | SD MISO / CS |
| 42 | LCD DC |
| 45 | LCD CS |

**With the camera plugged in, the only free signals are GPIO18, GPIO43, GPIO44, plus the shared I2C bus on 47/48.**

## Connections

| Module | Module pin | Board |
|---|---|---|
| MAX30102 | VIN | 3V3 (P2-1) |
|  | GND | GND (P2-2) |
|  | SDA | **GPIO48** (P2-6). Shares the bus with the QMI8658 IMU (0x6B); the MAX30102 is 0x57, so no clash. The board already has 4.7 k pull-ups. |
|  | SCL | **GPIO47** (P2-5) |
|  | INT | leave open; poll over I2C |
| Buzzer (active 3.3 V) | + | **GPIO18** (P1-6). A 5 V buzzer, or one drawing more than about 20 mA, needs an S8050 NPN and a 1 k base resistor. |
|  | − | GND |
| INMP441 | VDD / GND / L/R | 3V3 / GND / GND |
|  | SCK | **GPIO43** (P2-3) |
|  | WS | **GPIO44** (P2-4) |
|  | SD | **needs a third free pin, and GPIO18 is taken by the buzzer.** Choose: (a) wallet build: buzzer on 18, mic mounted but not wired; (b) camera build: mic SD on 18 and no buzzer. |
| Latching switch | 2 terminals | in series between TP4056 OUT+ and the board's BAT+ |
| TP4056 | B+ / B− | 18650 + / − |
|  | OUT+ / OUT− | switch → MX1.25 BAT + / BAT − (the plug that came with the board) |

## Cautions

- **MAX30102 I2C pull-ups.** Many purple boards pull up to 1.8 V. Move the board's solder jumper to **3.3 V**; otherwise SDA/SCL idle at about 2.5 V, right at the ESP32-S3's input threshold.
- **Buzzer through an S8050.** Put a 1N4148 across a magnetic buzzer (cathode to +).
- **Latching switch.** Use **COM and NO of one pole**; the other pole stays unused.
- **Cell.** Use a cell with welded tabs. Don't solder straight onto the can.

## Power notes

- The board has its own charger (ETA6098) behind its USB-C. The TP4056 gives a second, **charge-only** port with no data lines. That is part of the air-gap story: *"the port you charge from can't talk to the chip holding your keys."*
- With the latching switch OFF, the board is off (unless its own USB-C is plugged in). The TP4056 still charges the cell, because it sits on the cell side of the switch.
- **Never plug both USB-C ports at once.**
- For an air-gapped build after the hackathon, lock the data port down in firmware:
  - burn the eFuses that disable USB-Serial-JTAG and download mode;
  - enable secure boot.
- Use GPIO43 and GPIO44 only if logs go over native USB (Arduino: *USB CDC On Boot = Enabled*), because they are UART0.
