#!/usr/bin/env python3
"""
Generate a JSON Lines logfile with realistic LoRaWAN ABP uplinks.

Each line looks like:
{"gatewayEui": "...", "rxpk": { ... "data": "<base64 PHYPayload>" ... }}

Dependencies:
    pip install pycryptodome
"""

import json
import datetime
import base64

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

# ----------------------------------------------------------
# USER CONFIG
# ----------------------------------------------------------

# Gateway EUI (as you configured it in ChirpStack)
GATEWAY_EUI = "0102030405060708"

# LoRaWAN 1.0.x ABP session keys (16 bytes each, hex, big-endian as shown by LNS)
# Example dummy keys: CHANGE THESE TO YOUR OWN TEST KEYS
DEVADDR_HEX   = "26011BDA"  # DevAddr as shown in UI (big-endian); script will convert to little-endian in frame
NWK_SKEY_HEX  = "000102030405060708090A0B0C0D0E0F"
APP_SKEY_HEX  = "F0E0D0C0B0A090807060504030201000"

# Start frame counter (FCnt32)
FCNT_START = 0

# Number of frames to generate
NUM_FRAMES = 100

# Application payload (cleartext) – can be anything you like
# Here we use a simple byte string; you can change this to match your real device payload size.
APP_PAYLOAD = b"\x01\x02\x03\x04\x05\x06\x07\x08"

# LoRa radio metadata (rxpk fields) – adjust as needed
FREQ_MHZ = 868.3
DATARATE = "SF7BW125"
CODING_RATE = "4/5"

# Output file
OUT_FILE = "example_log_abp.jsonl"

# ----------------------------------------------------------
# HELPER FUNCTIONS
# ----------------------------------------------------------

def _clean_hex(s: str) -> str:
    return s.replace(" ", "").replace(":", "").replace("-", "").strip()


def hex_to_bytes(hex_str: str, expected_len: int | None = None) -> bytes:
    h = _clean_hex(hex_str)
    b = bytes.fromhex(h)
    if expected_len is not None and len(b) != expected_len:
        raise ValueError(f"Expected {expected_len} bytes, got {len(b)} for hex '{hex_str}'")
    return b


def devaddr_be_to_le(devaddr_hex: str) -> bytes:
    """
    DevAddr is usually written big-endian in UIs (e.g. 26011BDA),
    but in the LoRaWAN frame (FHDR) it is little-endian.
    """
    be = hex_to_bytes(devaddr_hex, 4)
    return be[::-1]  # reverse to little-endian


def encrypt_frm_payload(skey: bytes, devaddr_le: bytes, fcnt: int, direction: int, payload: bytes) -> bytes:
    """
    Encrypt FRMPayload using LoRaWAN spec AES-128.

    SKey      : AppSKey (FPort > 0) or NwkSKey (FPort == 0)
    DevAddr   : 4 bytes, little-endian (as in FHDR)
    FCnt      : 32-bit frame counter
    direction : 0 = uplink, 1 = downlink
    """
    if not payload:
        return b""

    cipher = AES.new(skey, AES.MODE_ECB)

    # Number of 16-byte blocks
    num_blocks = (len(payload) + 15) // 16
    enc = bytearray(len(payload))

    for block_index in range(1, num_blocks + 1):
        # Ai block (16 bytes)
        # 0      1..4          5         6..9         10..13       14     15
        # 0x01 | 0x00000000 | Dir | DevAddr | FCnt (LE) | 0x00 | block_index
        a = bytearray(16)
        a[0] = 0x01
        a[1] = 0x00
        a[2] = 0x00
        a[3] = 0x00
        a[4] = 0x00
        a[5] = direction & 0xFF
        a[6:10] = devaddr_le
        a[10] = fcnt & 0xFF
        a[11] = (fcnt >> 8) & 0xFF
        a[12] = (fcnt >> 16) & 0xFF
        a[13] = (fcnt >> 24) & 0xFF
        a[14] = 0x00
        a[15] = block_index & 0xFF

        s = cipher.encrypt(bytes(a))

        start = (block_index - 1) * 16
        end = min(block_index * 16, len(payload))
        for i in range(start, end):
            enc[i] = payload[i] ^ s[i - start]

    return bytes(enc)


def compute_mic(nwk_skey: bytes, devaddr_le: bytes, fcnt: int, direction: int, msg: bytes) -> bytes:
    """
    Compute MIC using LoRaWAN AES-CMAC (LoRaWAN 1.0.x).

    B0 = 0x49 | 0x00000000 | Dir | DevAddr | FCnt (LE) | 0x00 | len(msg)
    MIC = first 4 bytes of CMAC(NwkSKey, B0 | msg)
    """
    b0 = bytearray(16)
    b0[0] = 0x49
    b0[1] = 0x00
    b0[2] = 0x00
    b0[3] = 0x00
    b0[4] = 0x00
    b0[5] = direction & 0xFF
    b0[6:10] = devaddr_le
    b0[10] = fcnt & 0xFF
    b0[11] = (fcnt >> 8) & 0xFF
    b0[12] = (fcnt >> 16) & 0xFF
    b0[13] = (fcnt >> 24) & 0xFF
    b0[14] = 0x00
    b0[15] = len(msg) & 0xFF

    cmac = CMAC.new(nwk_skey, ciphermod=AES)
    cmac.update(bytes(b0) + msg)
    full_mic = cmac.digest()
    return full_mic[:4]


def build_abp_uplink(
    devaddr_le: bytes,
    nwk_skey: bytes,
    app_skey: bytes,
    fcnt: int,
    app_payload: bytes,
    fport: int = 1,
    confirmed: bool = False,
) -> bytes:
    """
    Build a LoRaWAN 1.0.x ABP uplink PHYPayload (un/confirmed data up).

    MHDR | FHDR | FPort | FRMPayload | MIC
    """
    # MHDR: MType + Major
    # Unconfirmed data up  = MType 2 -> 0x40
    # Confirmed data up    = MType 4 -> 0x80
    mhdr_val = 0x80 if confirmed else 0x40
    mhdr = bytes([mhdr_val])

    # FHDR: DevAddr (LE) | FCtrl | FCnt (LSB 2 bytes) | FOpts (none)
    fctrl = 0x00
    fcnt16 = fcnt & 0xFFFF
    fhdr = devaddr_le + bytes([fctrl, fcnt16 & 0xFF, (fcnt16 >> 8) & 0xFF])

    # FPort (1 byte)
    fport_b = bytes([fport & 0xFF])

    # FRMPayload encryption:
    # - if FPort == 0: NwkSKey
    # - if FPort > 0 : AppSKey
    s_key = nwk_skey if fport == 0 else app_skey
    direction = 0  # uplink
    enc_frmpayload = encrypt_frm_payload(s_key, devaddr_le, fcnt, direction, app_payload)

    mac_payload = fhdr + fport_b + enc_frmpayload

    # MIC is over MHDR | MACPayload
    mic = compute_mic(nwk_skey, devaddr_le, fcnt, direction, mhdr + mac_payload)

    phy_payload = mhdr + mac_payload + mic
    return phy_payload


# ----------------------------------------------------------
# MAIN: generate logfile
# ----------------------------------------------------------

def main():
    devaddr_le = devaddr_be_to_le(DEVADDR_HEX)
    nwk_skey = hex_to_bytes(NWK_SKEY_HEX, 16)
    app_skey = hex_to_bytes(APP_SKEY_HEX, 16)

    start_time = datetime.datetime(2025, 1, 1, 12, 0, 0)

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for i in range(NUM_FRAMES):
            fcnt = FCNT_START + i

            # Build PHYPayload for this frame
            phy = build_abp_uplink(
                devaddr_le=devaddr_le,
                nwk_skey=nwk_skey,
                app_skey=app_skey,
                fcnt=fcnt,
                app_payload=APP_PAYLOAD,
                fport=1,          # change to 0 if you want MAC-only messages
                confirmed=False,  # set True for confirmed uplink (MHDR 0x80)
            )

            base64_payload = base64.b64encode(phy).decode("ascii")

            t = start_time + datetime.timedelta(seconds=i * 10)

            rxpk = {
                "time": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tmst": 1000000 + i * 1000,
                "freq": FREQ_MHZ,
                "chan": 0,
                "rfch": 0,
                "stat": 1,
                "modu": "LORA",
                "datr": DATARATE,
                "codr": CODING_RATE,
                "rssi": -60 - (i % 20),
                "lsnr": 5.5 - (i % 10) * 0.1,
                "size": len(phy),
                "data": base64_payload,
            }

            rec = {
                "gatewayEui": GATEWAY_EUI,
                "rxpk": rxpk,
            }

            f.write(json.dumps(rec) + "\n")

    print(f"Written {NUM_FRAMES} frames to {OUT_FILE}")


if __name__ == "__main__":
    main()
