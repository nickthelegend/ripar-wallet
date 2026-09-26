// Waveshare ESP32-S3-LCD-2 pin map (from the official schematic) + Ripar wiring.
#pragma once

// ---- LCD: ST7789T3 240x320, SPI (shares MOSI/SCLK with the TF slot) ----
#define PIN_LCD_MOSI 38
#define PIN_LCD_SCLK 39
#define PIN_LCD_CS 45
#define PIN_LCD_DC 42
#define PIN_LCD_RST -1  // RC reset on the board
#define PIN_LCD_BL 1
#define PIN_SD_MISO 40
#define PIN_SD_CS 41

// ---- Camera (OV5640 / OV2640 on the 24-pin FPC) ----
#define PIN_CAM_PWDN 17
#define PIN_CAM_RESET -1
#define PIN_CAM_XCLK 8
#define PIN_CAM_SIOD 21
#define PIN_CAM_SIOC 16
#define PIN_CAM_D0 12  // Y2
#define PIN_CAM_D1 13
#define PIN_CAM_D2 15
#define PIN_CAM_D3 11
#define PIN_CAM_D4 14
#define PIN_CAM_D5 10
#define PIN_CAM_D6 7
#define PIN_CAM_D7 2  // Y9
#define PIN_CAM_VSYNC 6
#define PIN_CAM_HREF 4
#define PIN_CAM_PCLK 9

// ---- Shared I2C: QMI8658 IMU (0x6B) + MAX30102 pulse sensor (0x57) ----
#define PIN_I2C_SDA 48
#define PIN_I2C_SCL 47
#define I2C_ADDR_IMU 0x6B
#define I2C_ADDR_MAX30102 0x57
#define PIN_IMU_INT1 3

// ---- Keys / feedback / power ----
#define PIN_BOOT 0      // BOOT key = SIGN / NEXT (pressed by the printed Sign_Pin). Strapping pin: never
                        // require it held at power-on.
#define PIN_BUZZER 18   // header P1-6 (the only free GPIO with the camera attached)
#define PIN_BAT_ADC 5   // VBAT through 200k/100k divider

// ---- Optional INMP441 (I2S). Shares pins with the buzzer: see docs/WIRING.md ----
#define PIN_MIC_SCK 43
#define PIN_MIC_WS 44
#define PIN_MIC_SD 18

#define LCD_W 320  // landscape
#define LCD_H 240
