#!/usr/bin/env python3
import os
import json
import socket
import base64
import datetime
import io
from flask import Flask, request, render_template_string, url_for, send_file
import make_test_log

app = Flask(__name__)

STYLE_BLOCK = """
  <style>
    :root {
      color-scheme: light;
      font-family: "Inter", "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      --bg: linear-gradient(135deg, #eef2ff, #fdf2f8);
      --card-bg: #fff;
      --card-shadow: rgba(15, 23, 42, 0.08);
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --text-muted: #6b7280;
      --border: #e5e7eb;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      background: var(--bg);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem;
      color: #0f172a;
    }

    .outer-column {
      width: min(900px, 100%);
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
      align-items: center;
    }

    .logo-card {
      width: 100%;
      background: transparent;
      border-radius: 24px;
      box-shadow: none;
      border: none;
      padding: 1.5rem;
      text-align: center;
    }

    .logo-card img {
      max-width: 240px;
      width: 50%;
      height: auto;
    }

    .card {
      width: min(900px, 100%);
      background: var(--card-bg);
      border-radius: 24px;
      box-shadow: 0 24px 70px var(--card-shadow);
      padding: 3rem;
      border: 1px solid var(--border);
    }

    h1 {
      margin: 0 0 0.4rem;
      font-size: 2.05rem;
    }

    .subtitle {
      margin: 0 0 2rem;
      color: var(--text-muted);
      font-size: 1rem;
    }

    form {
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }

    label {
      font-weight: 600;
      margin-bottom: 0.4rem;
    }

    label + input,
    label + select {
      margin-top: 0.35rem;
    }

    .field-group {
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
    }

    .field-header {
      font-weight: 600;
    }

    .field-controls {
      position: relative;
      display: flex;
      align-items: center;
    }

    .input-with-actions {
      flex: 1;
    }

    .field-tools {
      position: absolute;
      right: 0.4rem;
      display: inline-flex;
      gap: 0.3rem;
      background: #fff;
      padding-left: 0.3rem;
    }

    .icon-button {
      border: 1px solid var(--border);
      background: #fff;
      border-radius: 8px;
      width: 32px;
      height: 32px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 0.85rem;
      color: var(--accent);
      cursor: pointer;
      transition: border-color 0.2s, color 0.2s, background 0.2s;
    }

    .icon-button:hover {
      border-color: var(--accent);
      background: rgba(37, 99, 235, 0.05);
    }

    .inline-action {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.35rem 0.75rem;
      border-radius: 999px;
      background: rgba(37, 99, 235, 0.12);
      color: var(--accent);
      font-size: 0.85rem;
      text-decoration: none;
      border: 1px solid rgba(37, 99, 235, 0.25);
      transition: background 0.2s, color 0.2s, border-color 0.2s;
    }

    .inline-action:hover {
      background: rgba(37, 99, 235, 0.18);
      color: var(--accent-hover);
      border-color: rgba(37, 99, 235, 0.4);
    }

    .inline-action span {
      font-weight: 600;
    }

    .inline-action-row {
      margin-bottom: 0.5rem;
    }

    .logfile-options {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 0.85rem;
      margin-top: 0.25rem;
    }

    .logfile-option {
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1rem;
      background: #f8fafc;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      height: 100%;
    }

    .logfile-option h3 {
      margin: 0;
      font-size: 1.05rem;
    }

    .logfile-option .hint {
      margin: 0;
    }

    .option-actions {
      margin-top: auto;
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
    }

    .option-actions .secondary-button {
      width: 100%;
      justify-content: center;
      text-align: center;
    }

    input[type=text],
    input[type=number],
    input[type=file],
    input[type=datetime-local],
    select {
      width: 100%;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.65rem 0.75rem;
      font-size: 1rem;
      transition: border-color 0.2s, box-shadow 0.2s;
    }

    input[type=text]:focus,
    input[type=number]:focus,
    input[type=file]:focus,
    input[type=datetime-local]:focus,
    select:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
    }

    .hint {
      font-size: 0.9rem;
      color: var(--text-muted);
      margin-top: 0.35rem;
    }

    button {
      padding: 0.9rem 1.4rem;
      border-radius: 12px;
      border: none;
      font-size: 1rem;
      font-weight: 600;
      background: var(--accent);
      color: white;
      cursor: pointer;
      transition: background 0.2s, transform 0.1s;
    }

    button:hover {
      background: var(--accent-hover);
    }

    button:active {
      transform: translateY(1px);
    }

    .form-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.8rem;
      align-items: center;
    }

    .secondary-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.85rem 1.2rem;
      border-radius: 12px;
      border: 1px solid var(--border);
      color: var(--accent);
      font-weight: 600;
      text-decoration: none;
      transition: border-color 0.2s, color 0.2s;
    }

    .secondary-button:hover {
      border-color: var(--accent);
      color: var(--accent-hover);
    }

    .form-actions button,
    .form-actions .secondary-button {
      flex: 1;
      min-width: 180px;
      justify-content: center;
      text-align: center;
    }

    .payload-examples {
      margin-top: 0.7rem;
      padding: 0.9rem;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #f8fafc;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }

    .payload-examples label {
      margin: 0;
      font-weight: 600;
      font-size: 0.95rem;
      color: #0f172a;
    }

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 1rem;
      margin-bottom: 1rem;
    }

    .file-drop {
      border: 1px dashed var(--accent);
      border-radius: 14px;
      padding: 1.1rem;
      background: linear-gradient(135deg, rgba(37, 99, 235, 0.08), rgba(37, 99, 235, 0.16));
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      cursor: pointer;
      transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
    }

    .file-drop:hover {
      border-color: var(--accent);
      box-shadow: 0 14px 34px rgba(37, 99, 235, 0.14);
      background: linear-gradient(135deg, rgba(37, 99, 235, 0.12), rgba(37, 99, 235, 0.2));
    }

    .file-drop.dragover {
      border-color: var(--accent);
      background: linear-gradient(135deg, rgba(37, 99, 235, 0.16), rgba(37, 99, 235, 0.24));
    }

    .file-drop .file-text {
      display: flex;
      flex-direction: column;
      gap: 0.2rem;
    }

    .file-drop .file-text strong {
      font-size: 1rem;
      color: var(--accent);
    }

    .file-drop .file-selected {
      color: var(--text-muted);
      font-size: 0.9rem;
      word-break: break-all;
    }

    .file-drop .choose-button {
      padding: 0.65rem 1rem;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: #fff;
      font-weight: 600;
      color: var(--accent);
      transition: border-color 0.2s, color 0.2s;
    }

    .file-drop .choose-button:hover {
      border-color: var(--accent);
      color: var(--accent-hover);
    }

    @media (max-width: 540px) {
      .card-header {
        flex-direction: column;
        align-items: flex-start;
      }
    }

    .result {
      border-radius: 12px;
      padding: 0.9rem 1.1rem;
      font-size: 0.95rem;
      line-height: 1.4;
    }

    .result.success {
      background: #ecfdf5;
      border: 1px solid #34d399;
      color: #065f46;
    }

    .result.error {
      background: #fef2f2;
      border: 1px solid #f87171;
      color: #7f1d1d;
    }

    .log-wrapper {
      width: 100%;
    }

    .log-block {
      border-radius: 20px;
      border: 1px solid var(--border);
      background: #fff;
      box-shadow: 0 12px 40px rgba(15, 23, 42, 0.08);
      padding: 1.2rem 1.4rem;
      width: min(900px, 100%);
    }

    .log-block summary {
      cursor: pointer;
      font-weight: 600;
      color: var(--accent);
      outline: none;
      font-size: 1.05rem;
    }

    .log-controls {
      display: flex;
      justify-content: flex-end;
      margin-bottom: 0.6rem;
      gap: 0.6rem;
      flex-wrap: wrap;
      font-size: 0.9rem;
    }

    .log-controls select {
      width: auto;
      padding: 0.35rem 0.6rem;
      border-radius: 8px;
      border: 1px solid var(--border);
      font-size: 0.9rem;
    }

    .log-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 1rem;
      font-size: 0.9rem;
    }

    .log-table th,
    .log-table td {
      text-align: left;
      padding: 0.55rem;
      border-bottom: 1px solid var(--border);
    }

    .log-table th {
      font-weight: 600;
      color: var(--text-muted);
      font-size: 0.85rem;
    }

    .log-table th button {
      background: none;
      border: none;
      color: inherit;
      font: inherit;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.2rem;
      padding: 0;
    }

    .log-table th button.sorted-asc::after {
      content: "▲";
      font-size: 0.7rem;
      color: var(--accent);
    }

    .log-table th button.sorted-desc::after {
      content: "▼";
      font-size: 0.7rem;
      color: var(--accent);
    }

    .log-table tbody tr.ok td {
      color: #047857;
    }

    .log-table tbody tr.err td {
      color: #b91c1c;
    }

    .brand-note {
      font-size: 0.95rem;
      color: #475569;
      text-align: center;
      line-height: 1.4;
    }

    .brand-note a {
      color: var(--accent);
      font-weight: 600;
      text-decoration: none;
    }

    .brand-note a:hover {
      text-decoration: underline;
    }
  </style>
"""

SCRIPT_BLOCK = """
  <script>
    function randomHex(byteLength) {
      const array = new Uint8Array(byteLength);
      if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(array);
      } else {
        for (let i = 0; i < array.length; i++) {
          array[i] = Math.floor(Math.random() * 256);
        }
      }
      return Array.from(array, (byte) =>
        byte.toString(16).padStart(2, "0")
      ).join("").toUpperCase();
    }

    function generateField(fieldId, type) {
      let value = "";
      switch (type) {
        case "gateway_eui":
          value = randomHex(8);
          break;
        case "devaddr":
          value = randomHex(4);
          break;
        case "skey":
          value = randomHex(16);
          break;
        default:
          return;
      }
      const input = document.getElementById(fieldId);
      if (input) {
        input.value = value;
      }
    }

    function copyField(fieldId) {
      const input = document.getElementById(fieldId);
      if (!input) return;
      input.select();
      input.setSelectionRange(0, 99999);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(input.value || "");
    } else {
      document.execCommand("copy");
    }
    }

    function initLogTable() {
      const section = document.querySelector("[data-log-section]");
      if (!section) return;
      const table = section.querySelector("[data-log-table]");
      if (!table) return;
      const tbody = table.querySelector("tbody");
      const originalRows = Array.from(tbody.rows);
      const rowData = originalRows.map((row) => {
        const data = {
          index: row.dataset.index || "",
          status: (row.dataset.status || "").toLowerCase(),
          gateway: (row.dataset.gateway || "").toLowerCase(),
          freq: (row.dataset.freq || "").toLowerCase(),
          size: (row.dataset.size || "").toLowerCase(),
          message: (row.dataset.message || "").toLowerCase(),
        };
        return { element: row.cloneNode(true), data };
      });

      const numericColumns = new Set(["index", "freq", "size"]);
      let sortKey = null;
      let sortDir = 1;

      const limitSelect = section.querySelector("[data-log-limit]");

      function apply() {
        let rows = rowData.slice();

        if (sortKey) {
          rows = rows.sort((a, b) => {
            const aVal = a.data[sortKey] || "";
            const bVal = b.data[sortKey] || "";
            if (numericColumns.has(sortKey)) {
              const aNum = parseFloat(aVal) || 0;
              const bNum = parseFloat(bVal) || 0;
              return sortDir * (aNum - bNum);
            }
            return (
              sortDir *
              aVal.localeCompare(bVal, undefined, { sensitivity: "base" })
            );
          });
        }

        let limit = rows.length;
        if (limitSelect && limitSelect.value !== "all") {
          const parsed = parseInt(limitSelect.value, 10);
          if (!isNaN(parsed)) {
            limit = parsed;
          }
        }

        const fragment = document.createDocumentFragment();
        rows.slice(0, limit).forEach((row) => {
          fragment.appendChild(row.element.cloneNode(true));
        });
        tbody.innerHTML = "";
        tbody.appendChild(fragment);
      }

      section.querySelectorAll("[data-log-sort]").forEach((button) => {
        button.addEventListener("click", () => {
          const key = button.dataset.logSort;
          if (sortKey === key) {
            sortDir *= -1;
          } else {
            sortKey = key;
            sortDir = 1;
          }
          section
            .querySelectorAll("[data-log-sort]")
            .forEach((btn) => btn.classList.remove("sorted-asc", "sorted-desc"));
          button.classList.add(sortDir === 1 ? "sorted-asc" : "sorted-desc");
          apply();
        });
      });

      if (limitSelect) {
        limitSelect.addEventListener("change", apply);
      }

      apply();
    }

    document.addEventListener("DOMContentLoaded", () => {
      initLogTable();
      const drop = document.querySelector("[data-file-drop]");
      const input = document.getElementById("logfile");
      const selected = document.querySelector("[data-file-selected]");
      const payloadSelect = document.querySelector("[data-payload-example]");
      const payloadInput = document.getElementById("app_payload_hex");
      const fportInput = document.getElementById("fport");

      if (payloadSelect && payloadInput && fportInput) {
        payloadSelect.addEventListener("change", () => {
          const opt = payloadSelect.selectedOptions[0];
          const payload = opt?.value;
          const port = opt?.dataset.port;
          if (payload) {
            payloadInput.value = payload;
          }
          if (port) {
            fportInput.value = port;
          }
        });
      }

      if (drop && input && selected) {
        const updateLabel = () => {
          if (input.files && input.files.length > 0) {
            selected.textContent = input.files.length === 1 ? input.files[0].name : `${input.files.length} files selected`;
          } else {
            selected.textContent = "No file selected";
          }
        };

        drop.addEventListener("click", () => input.click());

        ["dragenter", "dragover"].forEach((evt) =>
          drop.addEventListener(evt, (e) => {
            e.preventDefault();
            e.stopPropagation();
            drop.classList.add("dragover");
          })
        );
        ["dragleave", "drop"].forEach((evt) =>
          drop.addEventListener(evt, (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (evt === "drop" && e.dataTransfer?.files?.length) {
              const dt = new DataTransfer();
              Array.from(e.dataTransfer.files).forEach((file) => dt.items.add(file));
              input.files = dt.files;
              updateLabel();
            }
            drop.classList.remove("dragover");
          })
        );

        input.addEventListener("change", updateLabel);
        updateLabel();
      }
    });
  </script>
"""

HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>LoRaWAN Log Replay</title>
  <link rel="icon" type="image/x-icon" href="{{ favicon_url }}">
  {{ style_block|safe }}
</head>
<body>
  <div class="outer-column">
    <div class="logo-card">
      <img src="{{ logo_url }}" alt="Smart Parks logo">
    </div>

    <div class="card">
      <h1>LoRaWAN Log Replay</h1>
      <p class="subtitle">Replay recorded Semtech UDP uplinks towards your LoRaWAN server.</p>

      <form method="POST" action="{{ replay_url }}" enctype="multipart/form-data">
        <div>
          <label for="host">LoRaWAN server host</label>
          <input id="host" name="host" type="text" value="127.0.0.1">
          <div class="hint">Use <code>127.0.0.1</code> or <code>localhost</code> when this app runs on the same server as your LoRaWAN stack.</div>
        </div>

        <div>
          <label for="port">UDP port</label>
          <input id="port" name="port" type="number" value="1700">
          <div class="hint">The default Semtech UDP port is 1700.</div>
        </div>

        <div>
          <label for="logfile">Logfile</label>
          <div class="logfile-options">
            <div class="logfile-option">
              <h3>Upload a logfile</h3>
              <input id="logfile" type="file" name="logfile" required style="display: none;" aria-hidden="true">
              <div class="file-drop" data-file-drop>
                <div class="file-text">
                  <strong>Click to choose or drag & drop</strong>
                  <div class="file-selected" data-file-selected>No file selected</div>
                  <div class="hint">Upload a JSON Lines file you captured earlier.</div>
                </div>
              </div>
            </div>
            <div class="logfile-option">
              <h3>Generate a sample logfile</h3>
              <div class="hint">Download a ready-made JSONL sample.</div>
              <div class="option-actions">
                <a class="secondary-button" href="{{ generator_url }}" title="Generate a sample logfile" aria-label="Generate a sample logfile">Generate sample</a>
              </div>
            </div>
          </div>
        </div>

        <button type="submit">Replay</button>

        {% if result_lines %}
        <div class="result {{ result_class }}">
          {% for line in result_lines %}
          <div>{{ line }}</div>
          {% endfor %}
        </div>
        {% endif %}

      </form>
    </div>

    <p class="brand-note">
      A Smart Parks tool to Protect Wildlife with Passion and Technology.
      <a href="https://www.smartparks.org" target="_blank" rel="noopener">www.smartparks.org</a>
    </p>

    {% if log_lines %}
    <div class="log-wrapper" data-log-section>
      <details class="log-block">
        <summary>Show replay log</summary>
        <div class="log-controls">
          <label>
            Rows to display:
            <select data-log-limit>
              <option value="20">20</option>
              <option value="50">50</option>
              <option value="100">100</option>
              <option value="all">All</option>
            </select>
          </label>
        </div>
        <div style="overflow-x: auto;">
          <table class="log-table" data-log-table>
            <thead>
              <tr>
                <th><button type="button" data-log-sort="index">#</button></th>
                <th><button type="button" data-log-sort="status">Status</button></th>
                <th><button type="button" data-log-sort="gateway">Gateway EUI</button></th>
                <th><button type="button" data-log-sort="freq">Frequency</button></th>
                <th><button type="button" data-log-sort="size">Size</button></th>
                <th><button type="button" data-log-sort="message">Message</button></th>
              </tr>
            </thead>
            <tbody>
              {% for log_line in log_lines %}
              <tr class="{{ log_line.css }}"
                  data-index="{{ log_line.index }}"
                  data-status="{{ log_line.status }}"
                  data-gateway="{{ log_line.gateway or '' }}"
                  data-freq="{{ log_line.freq or '' }}"
                  data-size="{{ log_line.size or '' }}"
                  data-message="{{ (log_line.message or '') | e }}">
                <td>{{ log_line.index }}</td>
                <td>{{ log_line.status }}</td>
                <td>{{ log_line.gateway or "-" }}</td>
                <td>{{ log_line.freq or "-" }}</td>
                <td>{{ log_line.size or "-" }}</td>
                <td>{{ log_line.message }}</td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </details>
    </div>
    {% endif %}
  </div>
  {{ script_block|safe }}
</body>
</html>
"""

GENERATOR_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Generate LoRaWAN Test Log</title>
  <link rel="icon" type="image/x-icon" href="{{ favicon_url }}">
  {{ style_block|safe }}
</head>
<body>
  <div class="outer-column">
    <div class="logo-card">
      <img src="{{ logo_url }}" alt="Smart Parks logo">
    </div>

    <div class="card">
      <div class="card-header">
        <div>
          <h1>Generate Test Logfile</h1>
          <p class="subtitle">Configure LoRaWAN ABP parameters and download a JSON Lines log.</p>
        </div>
        <a class="secondary-button" href="{{ replay_url }}">Back to Replay</a>
      </div>

      <form method="POST" action="{{ generator_url }}">
        <div class="field-group">
          <div class="field-header">
            <label for="gateway_eui">Gateway EUI</label>
          </div>
          <div class="field-controls">
            <input class="input-with-actions" id="gateway_eui" name="gateway_eui" type="text" value="{{ form_values.gateway_eui }}" required>
            <div class="field-tools">
              <button type="button" class="icon-button" onclick="generateField('gateway_eui', 'gateway_eui')" title="Generate Gateway EUI">↻</button>
              <button type="button" class="icon-button" onclick="copyField('gateway_eui')" title="Copy Gateway EUI">⧉</button>
            </div>
          </div>
          <div class="hint">16 hex characters, e.g. 0102030405060708.</div>
        </div>

        <div class="field-group">
          <div class="field-header">
            <label for="devaddr_hex">DevAddr (hex, big-endian)</label>
          </div>
          <div class="field-controls">
            <input class="input-with-actions" id="devaddr_hex" name="devaddr_hex" type="text" value="{{ form_values.devaddr_hex }}" required>
            <div class="field-tools">
              <button type="button" class="icon-button" onclick="generateField('devaddr_hex', 'devaddr')" title="Generate DevAddr">↻</button>
              <button type="button" class="icon-button" onclick="copyField('devaddr_hex')" title="Copy DevAddr">⧉</button>
            </div>
          </div>
        </div>

        <div class="field-group">
          <div class="field-header">
            <label for="nwk_skey_hex">NwkSKey (hex)</label>
          </div>
          <div class="field-controls">
            <input class="input-with-actions" id="nwk_skey_hex" name="nwk_skey_hex" type="text" value="{{ form_values.nwk_skey_hex }}" required>
            <div class="field-tools">
              <button type="button" class="icon-button" onclick="generateField('nwk_skey_hex', 'skey')" title="Generate NwkSKey">↻</button>
              <button type="button" class="icon-button" onclick="copyField('nwk_skey_hex')" title="Copy NwkSKey">⧉</button>
            </div>
          </div>
        </div>

        <div class="field-group">
          <div class="field-header">
            <label for="app_skey_hex">AppSKey (hex)</label>
          </div>
          <div class="field-controls">
            <input class="input-with-actions" id="app_skey_hex" name="app_skey_hex" type="text" value="{{ form_values.app_skey_hex }}" required>
            <div class="field-tools">
              <button type="button" class="icon-button" onclick="generateField('app_skey_hex', 'skey')" title="Generate AppSKey">↻</button>
              <button type="button" class="icon-button" onclick="copyField('app_skey_hex')" title="Copy AppSKey">⧉</button>
            </div>
          </div>
        </div>

        <div>
          <label for="fport">FPort</label>
          <input id="fport" name="fport" type="number" min="1" max="223" value="{{ form_values.fport }}" required>
        </div>

        <div>
          <label for="app_payload_hex">Application payload (hex)</label>
          <input id="app_payload_hex" name="app_payload_hex" type="text" value="{{ form_values.app_payload_hex }}" required>
          <div class="hint">Byte payload encoded as hex (e.g. 0102030405060708).</div>
          <div class="payload-examples">
            <label for="payload_example">Example payloads (optional)</label>
            <select id="payload_example" data-payload-example>
              <option value="">Choose an example payload...</option>
              {% for example in payload_examples %}
              <option value="{{ example.payload }}" data-port="{{ example.port }}">{{ example.label }}</option>
              {% endfor %}
            </select>
            <div class="hint">Selecting an example fills both payload and matching FPort.</div>
          </div>
        </div>

        <div>
          <label for="fcnt_start">Frame counter start</label>
          <input id="fcnt_start" name="fcnt_start" type="number" value="{{ form_values.fcnt_start }}" min="0" required>
        </div>

        <div>
          <label for="num_frames">Number of frames</label>
          <input id="num_frames" name="num_frames" type="number" value="{{ form_values.num_frames }}" min="1" required>
        </div>

        <div>
          <label for="freq_mhz">Frequency (MHz)</label>
          <select id="freq_mhz" name="freq_mhz" required>
            {% for freq in freq_options %}
            <option value="{{ freq }}" {% if form_values.freq_mhz == freq %}selected{% endif %}>{{ freq }} MHz</option>
            {% endfor %}
          </select>
        </div>

        <div>
          <label for="datarate">Data rate</label>
          <select id="datarate" name="datarate" required>
            {% for dr in datarate_options %}
            <option value="{{ dr }}" {% if form_values.datarate == dr %}selected{% endif %}>{{ dr }}</option>
            {% endfor %}
          </select>
        </div>

        <div>
          <label for="coding_rate">Coding rate</label>
          <select id="coding_rate" name="coding_rate" required>
            {% for cr in coding_rate_options %}
            <option value="{{ cr }}" {% if form_values.coding_rate == cr %}selected{% endif %}>{{ cr }}</option>
            {% endfor %}
          </select>
        </div>

        <div>
          <label for="start_time">Start time (UTC)</label>
          <input id="start_time" name="start_time" type="datetime-local" value="{{ form_values.start_time }}" required>
        </div>

        <div>
          <label for="interval_seconds">Interval between frames (seconds)</label>
          <input id="interval_seconds" name="interval_seconds" type="number" min="1" value="{{ form_values.interval_seconds }}" required>
        </div>

        <div>
          <label for="out_file">Download filename</label>
          <input id="out_file" name="out_file" type="text" value="{{ form_values.out_file }}" required>
        </div>

        {% if error_message %}
        <div class="result error">{{ error_message }}</div>
        {% endif %}

        <div class="form-actions">
          <button type="submit">Generate</button>
          <a class="secondary-button" href="{{ replay_url }}">Back to Replay</a>
        </div>
      </form>
    </div>

    <p class="brand-note">
      A Smart Parks tool to Protect Wildlife with Passion and Technology.
      <a href="https://www.smartparks.org" target="_blank" rel="noopener">www.smartparks.org</a>
    </p>
  </div>
  {{ script_block|safe }}
</body>
</html>
"""

LOG_GENERATOR_DEFAULTS = {
    "gateway_eui": "0102030405060708",
    "devaddr_hex": "26011BDA",
    "nwk_skey_hex": "000102030405060708090A0B0C0D0E0F",
    "app_skey_hex": "F0E0D0C0B0A090807060504030201000",
    "app_payload_hex": "0102030405060708",
    "fcnt_start": "0",
    "num_frames": "100",
    "freq_mhz": "868.3",
    "datarate": "SF7BW125",
    "coding_rate": "4/5",
    "fport": "1",
    "start_time": "2025-01-01T12:00",
    "interval_seconds": "10",
    "out_file": "example_log_abp.jsonl",
}

PAYLOAD_EXAMPLES = [
    {
        "label": "Port 2 — f21e0100005300b3a40d1f4a110e0329fa000003051e0004f37a256900000000",
        "port": "2",
        "payload": "f21e0100005300b3a40d1f4a110e0329fa000003051e0004f37a256900000000",
    },
    {
        "label": "Port 4 — f40e04209300950f7d7f8b176f550002",
        "port": "4",
        "payload": "f40e04209300950f7d7f8b176f550002",
    },
    {
        "label": "Port 13 — 930ef77a2569b3a40d1f4a110e031e00",
        "port": "13",
        "payload": "930ef77a2569b3a40d1f4a110e031e00",
    },
]

EU868_FREQ_OPTIONS = [
    "868.1",
    "868.3",
    "868.5",
    "867.1",
    "867.3",
    "867.5",
    "867.7",
    "867.9",
]

EU868_DATARATE_OPTIONS = [
    "SF12BW125",
    "SF11BW125",
    "SF10BW125",
    "SF9BW125",
    "SF8BW125",
    "SF7BW125",
    "SF7BW250",
]

EU868_CODING_RATE_OPTIONS = ["4/5", "4/6", "4/7", "4/8"]


def get_generator_form_values(overrides=None):
    values = dict(LOG_GENERATOR_DEFAULTS)
    if overrides:
        for key in values.keys():
            if key in overrides:
                values[key] = overrides[key]
    return values


def clean_hex(value: str) -> str:
    return value.replace(" ", "").replace(":", "").replace("-", "").strip()


def generate_logfile_bytes(form_values):
    gateway_eui = form_values["gateway_eui"].strip()
    if not gateway_eui:
        raise ValueError("Gateway EUI is required.")

    devaddr_hex = form_values["devaddr_hex"].strip()
    nwk_skey_hex = form_values["nwk_skey_hex"].strip()
    app_skey_hex = form_values["app_skey_hex"].strip()
    app_payload_hex = clean_hex(form_values["app_payload_hex"])
    if not app_payload_hex:
        raise ValueError("Application payload must be provided.")

    try:
        devaddr_le = make_test_log.devaddr_be_to_le(devaddr_hex)
        nwk_skey = make_test_log.hex_to_bytes(nwk_skey_hex, 16)
        app_skey = make_test_log.hex_to_bytes(app_skey_hex, 16)
        app_payload = bytes.fromhex(app_payload_hex)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc

    fcnt_start = parse_int(form_values["fcnt_start"], "Frame counter start", minimum=0)
    num_frames = parse_int(form_values["num_frames"], "Number of frames", minimum=1)
    interval_seconds = parse_int(form_values["interval_seconds"], "Interval between frames", minimum=1)

    freq_choice = form_values["freq_mhz"].strip()
    if freq_choice not in EU868_FREQ_OPTIONS:
        raise ValueError("Select a valid EU868 frequency.")
    freq_mhz = float(freq_choice)

    datarate = form_values["datarate"].strip()
    if datarate not in EU868_DATARATE_OPTIONS:
        raise ValueError("Select a valid EU868 data rate.")

    coding_rate = form_values["coding_rate"].strip()
    if coding_rate not in EU868_CODING_RATE_OPTIONS:
        raise ValueError("Select a valid coding rate.")

    start_time_raw = form_values["start_time"].strip()
    if not start_time_raw:
        raise ValueError("Start time is required.")
    try:
        start_time = datetime.datetime.fromisoformat(start_time_raw)
    except ValueError as exc:
        raise ValueError("Start time must be in YYYY-MM-DDTHH:MM format.") from exc

    out_file = form_values["out_file"].strip() or "generated_log.jsonl"

    output = io.StringIO()
    for i in range(num_frames):
        fcnt = fcnt_start + i
        fport = parse_int(form_values.get("fport", "1"), "FPort", minimum=1, maximum=223)
        phy = make_test_log.build_abp_uplink(
            devaddr_le=devaddr_le,
            nwk_skey=nwk_skey,
            app_skey=app_skey,
            fcnt=fcnt,
            app_payload=app_payload,
            fport=fport,
            confirmed=False,
        )

        base64_payload = base64.b64encode(phy).decode("ascii")
        timestamp = start_time + datetime.timedelta(seconds=i * interval_seconds)
        rxpk = {
            "time": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tmst": 1000000 + i * 1000,
            "freq": freq_mhz,
            "chan": 0,
            "rfch": 0,
            "stat": 1,
            "modu": "LORA",
            "datr": datarate,
            "codr": coding_rate,
            "rssi": -60 - (i % 20),
            "lsnr": 5.5 - (i % 10) * 0.1,
            "size": len(phy),
            "data": base64_payload,
        }
        rec = {"gatewayEui": gateway_eui, "rxpk": rxpk}
        output.write(json.dumps(rec) + "\n")

    buffer = io.BytesIO(output.getvalue().encode("utf-8"))
    buffer.seek(0)
    return buffer, out_file


def parse_int(value, field, minimum=None, maximum=None):
    try:
        num = int(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be an integer.") from exc
    if minimum is not None and num < minimum:
        raise ValueError(f"{field} must be >= {minimum}.")
    if maximum is not None and num > maximum:
        raise ValueError(f"{field} must be <= {maximum}.")
    return num


def render_main_page(result_lines=None, result_class="", log_lines=None):
    return render_template_string(
        HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=url_for("static", filename="company_logo.png"),
        favicon_url=url_for("static", filename="favicon.ico"),
        replay_url=url_for("replay"),
        generator_url=url_for("generate_log_page"),
        result_lines=result_lines or [],
        result_class=result_class,
        log_lines=log_lines or [],
    )


def render_generator_page(form_values=None, error_message=""):
    values = form_values if form_values is not None else get_generator_form_values()
    return render_template_string(
        GENERATOR_HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=url_for("static", filename="company_logo.png"),
        favicon_url=url_for("static", filename="favicon.ico"),
        generator_url=url_for("generate_log_page"),
        replay_url=url_for("index"),
        form_values=values,
        error_message=error_message,
        freq_options=EU868_FREQ_OPTIONS,
        datarate_options=EU868_DATARATE_OPTIONS,
        coding_rate_options=EU868_CODING_RATE_OPTIONS,
        payload_examples=PAYLOAD_EXAMPLES,
    )


@app.route("/", methods=["GET"])
def index():
    return render_main_page()


@app.route("/replay", methods=["POST"])
def replay():
    host = request.form.get("host", "").strip() or "127.0.0.1"
    port_raw = request.form.get("port", "1700").strip()
    logfile = request.files.get("logfile")
    log_lines = []

    if not logfile:
        return render_main_page(["Please upload a logfile."], "error")

    try:
        port = int(port_raw)
    except ValueError:
        return render_main_page([f"Invalid UDP port: {port_raw}"], "error")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    total = 0
    errors = 0

    # Expected: JSON lines, 1 JSON object per line:
    # { "gatewayEui": "0102030405060708", "rxpk": { ... } }
    for raw_line in logfile.stream:
        try:
            line = raw_line.decode("utf-8").strip()
        except UnicodeDecodeError:
            errors += 1
            log_lines.append(
                {
                    "index": total + errors,
                    "status": "Error",
                    "gateway": None,
                    "freq": None,
                    "size": None,
                    "message": f"Skipped line: invalid UTF-8 encoding (target {host}:{port}).",
                    "css": "err",
                }
            )
            continue

        if not line:
            continue

        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            errors += 1
            print("JSON error:", e, "line:", line)
            preview = (line[:100] + "...") if len(line) > 100 else line
            log_lines.append(
                {
                    "index": total + errors,
                    "status": "Error",
                    "gateway": None,
                    "freq": None,
                    "size": None,
                    "message": f"Skipped line: JSON decode error ({e}) -- {preview}",
                    "css": "err",
                }
            )
            continue

        gateway_eui = rec.get("gatewayEui") or rec.get("gateway_eui")
        rxpk = rec.get("rxpk")

        if not gateway_eui or not rxpk:
            errors += 1
            print("Missing gatewayEui or rxpk:", line)
            snippet = ""
            if isinstance(rec, dict):
                try:
                    snippet = json.dumps(rec)[:100]
                except Exception:
                    snippet = str(rec)[:100]
            log_lines.append(
                {
                    "index": total + errors,
                    "status": "Error",
                    "gateway": gateway_eui,
                    "freq": rxpk.get("freq") if isinstance(rxpk, dict) else None,
                    "size": rxpk.get("size") if isinstance(rxpk, dict) else None,
                    "message": f"Skipped line: missing gatewayEui or rxpk. {snippet}",
                    "css": "err",
                }
            )
            continue

        try:
            packet = build_push_data(gateway_eui, rxpk)
        except Exception as e:
            errors += 1
            print("Build packet error:", e, "rec:", rec)
            try:
                rxpk_serialized = json.dumps(rxpk)
            except Exception:
                rxpk_serialized = str(rxpk) if rxpk is not None else ""
            rxpk_preview = rxpk_serialized[:100] + "..." if len(rxpk_serialized) > 100 else rxpk_serialized
            log_lines.append(
                {
                    "index": total + errors,
                    "status": "Error",
                    "gateway": gateway_eui,
                    "freq": rxpk.get("freq"),
                    "size": rxpk.get("size"),
                    "message": f"Build error: {e} -- {rxpk_preview}",
                    "css": "err",
                }
            )
            continue

        try:
            sock.sendto(packet, (host, port))
            total += 1
            freq = rxpk.get("freq", "?")
            size = rxpk.get("size", len(packet))
            datr = rxpk.get("datr", "?")
            rssi = rxpk.get("rssi", "?")
            lsnr = rxpk.get("lsnr", "?")
            time_str = rxpk.get("time", "?")
            payload = rxpk.get("data", "")
            payload_preview = (payload[:60] + "...") if payload and len(payload) > 60 else payload or "n/a"
            log_lines.append(
                {
                    "index": total + errors,
                    "status": "Sent",
                    "gateway": gateway_eui,
                    "freq": freq,
                    "size": size,
                    "message": f"{time_str} datr={datr}, rssi={rssi} dBm, lsnr={lsnr} dB, data={payload_preview}",
                    "css": "ok",
                }
            )
        except Exception as e:
            errors += 1
            print("Send error:", e)
            try:
                rxpk_serialized = json.dumps(rxpk)
            except Exception:
                rxpk_serialized = str(rxpk) if rxpk is not None else ""
            rxpk_preview = rxpk_serialized[:100] + "..." if len(rxpk_serialized) > 100 else rxpk_serialized
            log_lines.append(
                {
                    "index": total + errors,
                    "status": "Error",
                    "gateway": gateway_eui,
                    "freq": rxpk.get("freq"),
                    "size": rxpk.get("size"),
                    "message": f"Send error: {e} -- {rxpk_preview}",
                    "css": "err",
                }
            )

    sock.close()

    result = [
        "Replay done.",
        f"Sent={total}, errors={errors}",
        f"Target={host}:{port}",
    ]
    return render_main_page(result, "success", log_lines=log_lines)


@app.route("/generate-log", methods=["GET", "POST"])
def generate_log_page():
    if request.method == "GET":
        return render_generator_page()

    form_values = get_generator_form_values(request.form)
    try:
        log_buffer, filename = generate_logfile_bytes(form_values)
    except ValueError as exc:
        return render_generator_page(form_values=form_values, error_message=str(exc))

    return send_file(
        log_buffer,
        mimetype="application/jsonl",
        as_attachment=True,
        download_name=filename,
    )


def normalize_gateway_eui(gw_hex: str) -> bytes:
    """
    Takes a gateway EUI as hex string:
    - '0102030405060708'
    - or with ':' or '-' ('01:02:03:04:05:06:07:08')
    and returns 8 bytes.
    """
    gw_hex = gw_hex.replace(":", "").replace("-", "").strip()
    if len(gw_hex) != 16:
        raise ValueError(f"Gateway EUI must be 8 bytes (16 hex chars), got '{gw_hex}'")
    return bytes.fromhex(gw_hex)


def build_push_data(gateway_eui_hex: str, rxpk: dict) -> bytes:
    """
    Build a Semtech UDP PUSH_DATA packet:
    [0]    protocol version = 2
    [1-2]  random token
    [3]    identifier = 0x00 (PUSH_DATA)
    [4-11] gateway unique ID (8 bytes)
    JSON body: {"rxpk":[ rxpk ]}
    """
    # Header
    header = bytearray(12)
    header[0] = 0x02  # protocol version

    token = os.urandom(2)
    header[1] = token[0]
    header[2] = token[1]

    header[3] = 0x00  # PUSH_DATA

    gw_bytes = normalize_gateway_eui(gateway_eui_hex)
    header[4:12] = gw_bytes

    # Body
    body_obj = {"rxpk": [rxpk]}
    body = json.dumps(body_obj, separators=(",", ":")).encode("utf-8")

    return bytes(header) + body


if __name__ == "__main__":
    # Listen on all interfaces on port 8080
    app.run(host="0.0.0.0", port=8080, debug=True)
