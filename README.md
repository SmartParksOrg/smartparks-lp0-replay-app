# OpenCollar LP0 Replay tool
A local web app for replaying, decrypting, and decoding LoRaWAN uplinks from Semtech UDP JSONL logs.

## Setup

1) Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

2) Install dependencies:
```bash
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Open the app in your browser at `http://127.0.0.1:5000`.

## What it does

- Scan `.jsonl` LoRaWAN logs and summarize gateways and DevAddr values.
- Replay uplinks to a Semtech UDP forwarder with a configurable delay between packets.
- Manage device session keys and decode payloads with selectable decoders.
- Export decoded payloads as CSV or JSON.

## Generate Test Logs (optional)

You can generate a sample LoRaWAN ABP log from the web UI.  
Use the “Generate” form, then download the `.jsonl` output.

Or from the CLI:
```bash
python make_test_log.py
```

## Example: ChirpStack (Semtech UDP)

This tool sends Semtech UDP `PUSH_DATA` packets. To replay against ChirpStack, use the
Gateway Bridge in Semtech UDP mode.

1) In ChirpStack, create a Gateway with an EUI (for example `0102030405060708`).
2) Create an Application and Device Profile, then add the Device(s) you expect to
   see in the replay. For ABP devices, make sure the DevAddr / NwkSKey / AppSKey
   match the values used in your log generator or log file.
2) Ensure the ChirpStack Gateway Bridge is listening on UDP port `1700`
   (default for Semtech UDP).
3) Run this app and open the web UI.
4) Set the **LoRaWAN server host** to the Gateway Bridge host (often `127.0.0.1` if
   this app runs on the same machine) and **UDP port** to `1700`.
5) Upload a `.jsonl` log file (or generate one), then click **Start Replay**.

Notes:
- The `gatewayEui` in your log must match the Gateway EUI you created in ChirpStack.
- If ChirpStack is on another host, use its IP or DNS name.

## Notes

- Integrations (EarthRanger HTTP, InfluxDB, MQTT) are listed in the UI but not yet implemented.
- This tool is a local-only web app intended for inspecting and replaying LoRaWAN logs.
- Do not upload real device keys or production logs to public repos.
