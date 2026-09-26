# Vendor files (not in git)

The enclosure was fitted to Waveshare's official CAD for the **ESP32-S3-LCD-2**. Those files are Waveshare's and aren't redistributed here.

- 2D/3D archive: https://files.waveshare.com/wiki/ESP32-S3-LCD-2/ESP32-S3-LCD-2-2Dand3D.rar. It contains `ESP32-S3-LCD-2-20250122.stp` and a PDF drawing.
- Schematic: https://files.waveshare.com/wiki/ESP32-S3-LCD-2/ESP32-S3-Touch-LCD-2-SchDoc.pdf
- Wiki: https://www.waveshare.com/wiki/ESP32-S3-LCD-2

You don't need them to rebuild. `board_boxes.json` (committed) holds every component bounding box measured from the STEP. Those numbers were transcribed by hand into `design.BOARD`, and `cad/parts_board.py` builds a lightweight board model from them.

To reproduce the measurement:
1. Extract the `.stp` into this folder.
2. Run `python cad/board.py`. It imports the STEP into SolidWorks and saves `model/parts/Board_ESP32S3_LCD2.SLDPRT` (heavy and git-ignored). The per-component boxes were dumped from that import once.
