# bletrace

A workbench for reverse-engineering Bluetooth LE gadgets. It pulls a Bluetooth packet capture
off your iPhone over USB, decodes it down to the bytes each app writes, and shows them in a
browser GUI built for spotting patterns. Python standard library only, no installs.

## Start

```bash
cd /mnt/c/Users/maxwa/Documents/__projects/bletrace
./bletrace.sh gui          # opens http://localhost:8765 in your Windows browser
```

Run it in **WSL**. To pull captures, the iPhone must be attached to WSL (`usbipd.exe attach --wsl --busid <BUSID>`
then `sudo usbmuxd`; see `../xtool-commands.txt`). The dot in the top-right corner turns teal when it's connected.

## Capturing an app (iPhone)

1. Install Apple's **Bluetooth** logging profile on the phone (developer.apple.com/bug-reporting/profiles-and-logs),
   then restart the phone.
2. Close other apps that use the device. In the vendor app, do one action at a time, a few seconds apart,
   and write down the order (off, on, red, green, blue, bright, dim…).
3. Hold **both volume buttons + side button** about 1 s, until the phone vibrates. Wait 5 to 10 minutes.
4. In the GUI, choose **Pull capture from iPhone** (or run `./bletrace.sh pull`).

It also opens `.pklg` files from macOS PacketLogger and Android `btsnoop_hci.log` files (**Open file…**).
**Pull Luma log** imports LumaRemote's own `diagnostics.txt`, so you can compare what Luma sends with what the vendor app sends.

## Reading a capture

- **Trace strip** (top): every packet over time. Amber lines rising = the phone sent; teal lines hanging = the phone received.
  Each of your taps shows up as a burst; click one to jump to it. Notes appear as magenta flags.
- **Timeline**: magenta bytes changed since the previous packet of the same shape on the same
  characteristic. Dotted "pause" rows mark gaps, which line up with your taps.
- **Detail** (right): byte grid with decimal values, checksum guesses, and a note box. Note each burst
  with what you did ("tapped red"); notes are saved with the capture.
- **Byte patterns**: groups packets by characteristic, length and first byte. Magenta cells vary,
  plain cells are constant, dashed cells are the detected checksum.
- Double-click a characteristic in the sidebar to name it.

## Command line

```bash
./bletrace.sh list                     # captures
./bletrace.sh show latest              # writes + notifications as a table (--all for every ATT packet)
./bletrace.sh patterns latest          # byte patterns and checksum guesses
./bletrace.sh import file.pklg
./bletrace.sh pull [--luma]
python3 -m unittest discover -s tests  # tests
```

Captures live in `captures/<id>/` (raw file, `meta.json`, `notes.json`). An optional `bletrace.json`
overrides settings such as `luma_container`.
