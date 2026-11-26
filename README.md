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

## Example: DayBetter P09C bulbs

bletrace was built to work out the protocol of DayBetter P09C Bluetooth bulbs for
[LumaRemote](../LumaRemote/README.md), a replacement iOS app. Luma's commands were being silently ignored, so
the official app was captured doing one action every ~3 s (off, on, red, green, blue, dim, white), then
each burst was labeled in the GUI.

![Login handshake: the bulb's challenge, selected, with its byte grid and checksum guess](docs/login.png)

The timeline showed the official app doing one thing Luma didn't: a `"CCHIP"` login before any command.
The bulb replies with 2 random challenge bytes, and the app answers with **challenge XOR `24 4C`**.
Labeling each burst made the rest easy to read:

![Labeled timeline: power, color mode, red, green, blue, brightness and white](docs/color.png)

**Byte patterns** showed which positions vary and found the checksum (CRC-16/MODBUS, little-endian) without being told:

![Byte patterns grouped by characteristic, with varying bytes in magenta and the checksum dashed](docs/patterns.png)

### What the bytes mean

Every frame is `A0 cmd len payload… crcLo crcHi`, written to `A09C`. Replies are `A1 cmd …` on `F09C`.

| Sent (from the capture) | Meaning |
|---|---|
| `A0 00 08 43 43 48 49 50 AC CA` | Login hello: `"CCHIP"` |
| ← `A1 00 0A "CCHIP" 06 03 …` | Bulb's challenge: `06 03` |
| `A0 01 0A "CCHIP" 22 4F 28 4A` | Answer: `06^24 03^4C` = `22 4F` |
| ← `A1 01 09 "CCHIP" 00 …` | Login accepted |
| `A0 10 04 01 E0 E1` | Status request (45-byte reply) |
| `A0 11 04 00 70 E1` | Power off |
| `A0 11 04 01 B1 21` | Power on |
| `A0 12 04 01 41 21` | Color mode (`00` = white mode) |
| `A0 15 07 FE 01 00 00 6C 27` | Color `R G B 00`: red (where the color wheel landed) |
| `A0 15 07 00 FF 00 00 3C 3F` | Green |
| `A0 15 07 00 00 FF 00 4D FF` | Blue |
| `A0 13 04 19 10 EB` | Brightness `0x19` = 25 % |
| `A0 20 07 FF FF F0 0F 0D 8A` | White: warm/cool pair, `a + b = 255` |
| ← `A1 cmd 04 01 …` | Acknowledgement |

The last two bytes of every frame are the CRC, and `len` = total length − 2. The full write-up is in
`../LumaRemote/README.md`.

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
