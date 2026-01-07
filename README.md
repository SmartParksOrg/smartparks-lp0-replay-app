# smartparks-lp0-replay-app
A simple Web Application that acts as an UPD packet forwarder loaded with an lp0 log file.  

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

## Generate Test Logs (optional)

You can generate a sample LoRaWAN ABP log from the web UI.  
Use the “Generate” form, then download the `.jsonl` output.

Or from the CLI:
```bash
python make_test_log.py
```

## Notes

- This tool is a local-only web app intended for inspecting and replaying LoRaWAN logs.
- Do not upload real device keys or production logs to public repos.
