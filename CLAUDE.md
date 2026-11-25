# bletrace

BLE reverse-engineering workbench (see README.md). Python 3 stdlib only; the GUI is vanilla JS served
by `bletrace/server.py` on 127.0.0.1:8765. Runs in WSL; the browser is on Windows.

- `capture_io.py`: pklg (both byte orders) + btsnoop readers → `HciRecord`
- `decode.py`: HCI → ATT timeline, handle→UUID map from discovery, device names from adverts
- `analysis.py`: checksum guessing (CRC16/CRC8/sum/xor) and byte-pattern grouping
- `device.py`: libimobiledevice: `idevicecrashreport` (sysdiagnose → *.pklg), `afcclient` (Luma log)
- `store.py`: captures/ library + notes; `luma.py` parses LumaRemote's diagnostics.txt
- `static/`: GUI (index.html, style.css, app.js). Deep links: `/?capture=<id>&select=<i>&tab=patterns`

Test: `python3 -m unittest discover -s tests`. Visual check: run `./bletrace.sh gui --no-open` in the
background, then screenshot with headless Edge
(`msedge.exe --headless=new --window-size=1600,900 --screenshot=C:\...\shot.png "http://localhost:8765/?..."`).
To stop the server use `pkill -f "m bletrace gu[i]"`, not a pattern that also matches your own shell command.

Tarballs from the phone are untrusted: only `.pklg` members are read via `extractfile`, never extracted.
