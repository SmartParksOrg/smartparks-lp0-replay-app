#!/usr/bin/env python3
import os
import binascii
import secrets
import time
import json
import socket
import base64
import datetime
import io
import csv
import subprocess
import html
import threading
import urllib.parse
from flask import Flask, request, render_template_string, url_for, send_file, redirect, jsonify
from werkzeug.utils import secure_filename
import make_test_log

app = Flask(__name__)
SCAN_CACHE = {}
SCAN_CACHE_TTL = 30 * 60
DECODE_CACHE = {}
DECODE_CACHE_TTL = 30 * 60
REPLAY_CACHE = {}
REPLAY_CACHE_TTL = 30 * 60
REPLAY_LOCK = threading.Lock()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
DECODER_DIR = os.path.join(DATA_DIR, "decoders")
BUILTIN_DECODER_DIR = os.path.join(BASE_DIR, "decoders")
CREDENTIALS_PATH = os.path.join(DATA_DIR, "credentials.json")
UPLOAD_INDEX_PATH = os.path.join(DATA_DIR, "uploads.json")

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
      align-items: stretch;
      justify-content: stretch;
      padding: 1.5rem 2.5rem;
      color: #0f172a;
    }

    .outer-column {
      width: 100%;
      max-width: 1200px;
      display: flex;
      flex-direction: column;
      gap: 0.375rem;
      align-items: stretch;
      margin: 0 auto;
      position: relative;
    }

    .top-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 0.5rem 0.25rem 0;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .brand img {
      width: 52px;
      height: auto;
    }

    .brand-title {
      font-weight: 700;
      font-size: 1.05rem;
      letter-spacing: 0.01em;
    }

    .brand-subtitle {
      font-size: 0.85rem;
      color: var(--text-muted);
    }

    .menu-toggle {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 40px;
      height: 40px;
      border: 1px solid var(--border);
      background: #fff;
      border-radius: 12px;
      padding: 0;
      cursor: pointer;
      font-weight: 600;
      transition: border-color 0.2s, background 0.2s;
    }

    .menu-toggle span {
      display: block;
    }

    .menu-toggle .menu-label {
      display: none;
    }

    .menu-toggle .bar {
      width: 18px;
      height: 2px;
      background: #0f172a;
      border-radius: 999px;
      transition: transform 0.2s, opacity 0.2s;
    }

    .menu-toggle .bars {
      display: inline-flex;
      flex-direction: column;
      gap: 3px;
    }

    .menu-toggle.open .bar:nth-child(1) {
      transform: translateY(5px) rotate(45deg);
    }

    .menu-toggle.open .bar:nth-child(2) {
      opacity: 0;
    }

    .menu-toggle.open .bar:nth-child(3) {
      transform: translateY(-5px) rotate(-45deg);
    }

    .menu-panel {
      position: absolute;
      top: 4.5rem;
      right: 1.5rem;
      z-index: 50;
      max-width: 520px;
      background: #fff;
      border: 1px solid var(--border);
      border-radius: 16px;
      box-shadow: 0 20px 50px rgba(15, 23, 42, 0.12);
      padding: 0.75rem;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 0.35rem;
    }

    .menu-panel[hidden] {
      display: none;
    }

    .menu-link {
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 0.5rem 0.75rem;
      border-radius: 12px;
      text-decoration: none;
      color: #0f172a;
      font-weight: 600;
      border: 1px solid transparent;
      transition: border-color 0.2s, color 0.2s, background 0.2s;
    }

    .menu-link:hover {
      border-color: rgba(37, 99, 235, 0.4);
      background: rgba(37, 99, 235, 0.08);
      color: var(--accent-hover);
    }

    .menu-link.active {
      border-color: rgba(37, 99, 235, 0.6);
      background: rgba(37, 99, 235, 0.15);
      color: var(--accent);
    }

    .logo-card {
      width: 100%;
      background: transparent;
      border-radius: 24px;
      box-shadow: none;
      border: none;
      padding: 0.375rem;
      text-align: center;
    }

    .logo-card img {
      max-width: 120px;
      width: 25%;
      height: auto;
    }

    .card {
      width: 100%;
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
      min-width: 0;
    }

    .input-with-actions {
      flex: 1;
      min-width: 0;
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

    .toggle-visibility {
      position: absolute;
      right: 0.4rem;
      border: 1px solid var(--border);
      background: #fff;
      border-radius: 8px;
      width: 32px;
      height: 32px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 0.9rem;
      color: var(--accent);
      cursor: pointer;
      transition: border-color 0.2s, color 0.2s, background 0.2s;
    }

    .toggle-visibility:hover {
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

    .next-steps {
      margin-top: 1.5rem;
      padding: 1.25rem;
      border: 1px solid var(--border);
      border-radius: 16px;
      background: #f8fafc;
    }

    .next-steps h2 {
      margin: 0 0 0.6rem;
      font-size: 1.1rem;
    }

    .action-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 0.75rem;
    }

    input[type=text],
    input[type=number],
    input[type=file],
    input[type=datetime-local],
    input[type=password],
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
    input[type=password]:focus,
    select:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
    }

    input[type=password] {
      font-family: inherit;
      letter-spacing: normal;
    }

    .key-input {
      font-family: "IBM Plex Mono", "SFMono-Regular", "Menlo", monospace;
      font-size: 0.72rem;
      letter-spacing: -0.01em;
      font-variant-ligatures: none;
    }

    .hint {
      font-size: 0.9rem;
      color: var(--text-muted);
      margin-top: 0.35rem;
    }

    .simple-list {
      margin: 0.5rem 0 0;
      padding-left: 1.2rem;
      color: #0f172a;
    }

    .simple-list li {
      margin: 0.25rem 0;
    }

    .decoder-list {
      list-style: none;
      padding: 0;
      margin: 0.75rem 0 0;
      display: flex;
      flex-direction: column;
      gap: 0.6rem;
    }

    .decoder-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      padding: 0.6rem 0.75rem;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #f8fafc;
    }

    .decoder-link {
      color: #0f172a;
      text-decoration: none;
      font-weight: 600;
      word-break: break-all;
    }

    .decoder-link:hover {
      color: var(--accent-hover);
    }

    .decoder-meta {
      color: var(--text-muted);
      font-size: 0.85rem;
      margin-left: 0.5rem;
    }

    .decoder-actions {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
    }

    .file-actions {
      display: inline-flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.4rem;
    }

    .code-block {
      background: #0f172a;
      color: #e2e8f0;
      padding: 1rem;
      border-radius: 12px;
      font-family: "IBM Plex Mono", "SFMono-Regular", "Menlo", monospace;
      font-size: 0.85rem;
      line-height: 1.4;
      overflow: auto;
      max-height: 420px;
    }

    .scan-overlay {
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.55);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
      z-index: 80;
    }

    .scan-overlay[hidden] {
      display: none;
    }

    .scan-card {
      background: #fff;
      border-radius: 18px;
      padding: 1.75rem;
      width: min(560px, 95vw);
      box-shadow: 0 25px 70px rgba(15, 23, 42, 0.18);
      border: 1px solid var(--border);
    }

    .scan-card h2 {
      margin: 0 0 0.75rem;
      font-size: 1.3rem;
    }

    .scan-card .form-actions {
      margin-top: 1rem;
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

    button:disabled {
      background: #94a3b8;
      cursor: not-allowed;
      transform: none;
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
      background: #fff;
      color: var(--accent);
      font-weight: 600;
      text-decoration: none;
      transition: border-color 0.2s, color 0.2s;
    }

    .secondary-button:hover {
      background: #f8fafc;
      border-color: var(--accent);
      color: var(--accent-hover);
    }

    .danger-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
      border-radius: 8px;
      border: 1px solid #fecaca;
      background: #fee2e2;
      color: #b91c1c;
      cursor: pointer;
      transition: background 0.2s, border-color 0.2s;
    }

    .danger-button:hover {
      background: #fecaca;
      border-color: #fca5a5;
    }

    .danger-button.danger-text {
      width: auto;
      height: auto;
      padding: 0.35rem 0.7rem;
      font-size: 0.85rem;
      font-weight: 600;
      gap: 0.35rem;
    }

    .danger-button svg {
      width: 18px;
      height: 18px;
      display: block;
      fill: currentColor;
    }

    .stop-replay-button {
      background: #dc2626;
    }

    .stop-replay-button:hover {
      background: #b91c1c;
    }

    .start-replay-button,
    .resume-replay-button {
      background: #16a34a;
    }

    .start-replay-button:hover,
    .resume-replay-button:hover {
      background: #15803d;
    }

    .restart-replay-button {
      background: #f97316;
    }

    .restart-replay-button:hover {
      background: #ea580c;
    }

    .is-hidden {
      display: none;
    }

    .field-controls.key-controls {
      gap: 0.5rem;
    }

    .field-controls.key-controls .toggle-visibility {
      position: static;
    }

    .primary-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.85rem 1.4rem;
      border-radius: 12px;
      background: var(--accent);
      color: #fff;
      font-weight: 600;
      text-decoration: none;
      border: 1px solid transparent;
      transition: background 0.2s, transform 0.2s;
    }

    .primary-button:hover {
      background: var(--accent-hover);
      transform: translateY(-1px);
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
      body {
        padding: 1rem;
      }

      .card {
        padding: 2rem 1.5rem;
      }

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

    .result.info {
      background: #eff6ff;
      border: 1px solid #93c5fd;
      color: #1e3a8a;
    }

    .replay-status {
      margin-top: 1rem;
    }

    .log-wrapper {
      width: 100%;
    }

    .loading-overlay {
      position: fixed;
      inset: 0;
      background: rgba(255, 255, 255, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 50;
    }

    .loading-overlay[hidden] {
      display: none;
    }

    .loading-card {
      background: #fff;
      border-radius: 18px;
      box-shadow: 0 20px 60px rgba(15, 23, 42, 0.18);
      padding: 24px 28px;
      display: flex;
      align-items: center;
      gap: 16px;
      color: #0f172a;
      font-weight: 600;
    }

    .spinner {
      width: 32px;
      height: 32px;
      border: 4px solid rgba(15, 23, 42, 0.2);
      border-top-color: #2563eb;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }

    .log-block {
      border-radius: 20px;
      border: 1px solid var(--border);
      background: #fff;
      box-shadow: 0 12px 40px rgba(15, 23, 42, 0.08);
      padding: 1.2rem 1.4rem;
      width: 100%;
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

    .truncate-cell {
      max-width: 320px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      cursor: pointer;
    }

    .truncate-cell.expanded {
      white-space: pre-wrap;
      overflow: visible;
      text-overflow: unset;
      max-width: none;
      cursor: zoom-out;
    }

    .truncate-cell::after {
      content: " ⤢";
      color: var(--text-muted);
      font-size: 0.75rem;
    }

    .truncate-cell.expanded::after {
      content: " ⤡";
    }

    .cell-action {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.3rem 0.6rem;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: #fff;
      color: var(--accent);
      font-weight: 600;
      font-size: 0.85rem;
      cursor: pointer;
    }

    .cell-action:hover {
      border-color: var(--accent);
      color: var(--accent-hover);
    }

    .detail-overlay {
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.4);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
      z-index: 80;
    }

    .detail-overlay[hidden] {
      display: none;
    }

    .detail-card {
      width: min(900px, 100%);
      max-height: 85vh;
      background: #fff;
      border-radius: 18px;
      border: 1px solid var(--border);
      box-shadow: 0 18px 50px rgba(15, 23, 42, 0.2);
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }

    .detail-card h2 {
      margin: 0;
      font-size: 1.35rem;
    }

    .detail-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 0.75rem;
      font-size: 0.95rem;
    }

    .detail-block {
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 0.9rem;
      font-size: 0.9rem;
      max-height: 30vh;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }

    .detail-block pre {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: "SFMono-Regular", "Menlo", "Consolas", "Liberation Mono", monospace;
      font-size: 0.85rem;
    }

    .detail-collapsible summary {
      cursor: pointer;
      font-weight: 600;
      color: var(--accent);
    }

    .detail-actions {
      display: flex;
      justify-content: flex-end;
      gap: 0.6rem;
    }

    .detail-actions button {
      width: auto;
    }

    .section-divider {
      margin: 2rem 0;
      border-top: 1px solid var(--border);
    }

    .key-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 0.85rem;
    }

    .key-grid.add-device-grid {
      grid-template-columns: minmax(140px, 0.6fr) minmax(200px, 1fr) minmax(280px, 1.7fr) minmax(280px, 1.7fr);
      align-items: end;
    }

    .key-grid.device-grid {
      grid-template-columns: minmax(200px, 1fr) minmax(200px, 1fr) minmax(200px, 1fr) 52px;
      align-items: end;
    }

    .missing-keys-block {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 16px;
      padding: 1rem 1.2rem;
      box-shadow: 0 10px 30px rgba(15, 23, 42, 0.04);
    }

    .integration-block {
      background: #f8fafc;
      border-color: #e2e8f0;
      opacity: 0.7;
    }

    .integration-block .secondary-button,
    .integration-block button {
      background: #f1f5f9;
      border-color: #e2e8f0;
      color: #94a3b8;
      cursor: not-allowed;
      pointer-events: none;
    }

    .hint-divider {
      margin: 0.6rem 0 0.9rem;
      border-top: 1px dashed #cbd5f5;
    }

    .remove-cell {
      display: flex;
      justify-content: flex-end;
      align-items: flex-end;
      padding-bottom: 0.2rem;
    }

    @media (max-width: 900px) {
      .key-grid.add-device-grid {
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      }

      .key-grid.device-grid {
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      }

      .remove-cell {
        justify-content: flex-start;
      }
    }

    .device-rows {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }

    .device-row {
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1rem;
      background: #f8fafc;
    }

    .table-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.6rem;
      margin-top: 0.75rem;
    }

    .tag {
      display: inline-flex;
      align-items: center;
      padding: 0.2rem 0.6rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
      background: rgba(37, 99, 235, 0.12);
      color: var(--accent);
      border: 1px solid rgba(37, 99, 235, 0.2);
      margin-left: 0.4rem;
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

    .progress-bar {
      width: 220px;
      height: 10px;
      border-radius: 999px;
      background: #e2e8f0;
      overflow: hidden;
      position: relative;
    }

    .progress-bar::after {
      content: "";
      position: absolute;
      inset: 0;
      width: 40%;
      background: linear-gradient(90deg, rgba(37, 99, 235, 0.2), rgba(37, 99, 235, 0.9), rgba(37, 99, 235, 0.2));
      animation: progress-slide 1.1s ease-in-out infinite;
    }

    @keyframes progress-slide {
      0% { transform: translateX(-60%); }
      100% { transform: translateX(160%); }
    }

    .progress-track {
      width: 100%;
      height: 10px;
      border-radius: 999px;
      background: #e2e8f0;
      overflow: hidden;
      margin-top: 0.5rem;
    }

    .progress-fill {
      height: 100%;
      background: linear-gradient(90deg, #1d4ed8, #3b82f6);
      width: 0%;
      transition: width 0.2s ease-out;
    }

    .progress-meta {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.9rem;
      color: #475569;
      margin-top: 0.5rem;
      gap: 1rem;
      flex-wrap: wrap;
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

    function initSortableTable(section) {
      if (!section) return;
      const table = section.querySelector("[data-sortable-table]");
      if (!table) return;
      const tbody = table.querySelector("tbody");
      const originalRows = Array.from(tbody.rows);
      const rowData = originalRows.map((row) => {
        const data = {};
        Object.keys(row.dataset || {}).forEach((key) => {
          data[key] = (row.dataset[key] || "").toLowerCase();
        });
        return { element: row.cloneNode(true), data };
      });

      const numericColumns = new Set(
        (table.dataset.numericKeys || "").split(",").filter(Boolean)
      );
      let sortKey = null;
      let sortDir = 1;

      const limitSelect = section.querySelector("[data-table-limit]");

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

      section.querySelectorAll("[data-sort-key]").forEach((button) => {
        button.addEventListener("click", () => {
          const key = button.dataset.sortKey;
          if (sortKey === key) {
            sortDir *= -1;
          } else {
            sortKey = key;
            sortDir = 1;
          }
          section
            .querySelectorAll("[data-sort-key]")
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

    function initTruncation(section) {
      if (!section) return;
      section.querySelectorAll("[data-truncate]").forEach((cell) => {
        const full = cell.dataset.full || "";
        if (!full || full.length <= 80) {
          cell.textContent = full;
          return;
        }
        const preview = full.slice(0, 80) + "…";
        cell.textContent = preview;
        cell.classList.add("truncate-cell");
        cell.addEventListener("click", () => {
          const isExpanded = cell.classList.toggle("expanded");
          cell.textContent = isExpanded ? full : preview;
        });
      });
    }

    function initDetailOverlay(section) {
      if (!section) return;
      const overlay = document.querySelector("[data-detail-overlay]");
      if (!overlay) return;
      const title = overlay.querySelector("[data-detail-title]");
      const meta = overlay.querySelector("[data-detail-meta]");
      const payload = overlay.querySelector("[data-detail-payload]");
      const decoded = overlay.querySelector("[data-detail-decoded]");
      const closeBtn = overlay.querySelector("[data-detail-close]");

      const close = () => {
        overlay.hidden = true;
      };
      closeBtn?.addEventListener("click", close);
      overlay.addEventListener("click", (event) => {
        if (event.target === overlay) {
          close();
        }
      });

      section.addEventListener("click", (event) => {
        const btn = event.target.closest("[data-detail-trigger]");
        if (!btn) return;
        const row = btn.closest("tr");
        if (!row) return;
        title.textContent = `Packet #${row.dataset.index || "?"}`;
        meta.innerHTML = `
          <div><strong>Status:</strong> ${row.dataset.status || "-"}</div>
          <div><strong>DevAddr:</strong> ${row.dataset.devaddr || "-"}</div>
          <div><strong>FCnt:</strong> ${row.dataset.fcnt || "-"}</div>
          <div><strong>FPort:</strong> ${row.dataset.fport || "-"}</div>
          <div><strong>Time:</strong> ${row.dataset.time || "-"}</div>
        `;
        payload.textContent = row.dataset.payload || "";
        const decodedRaw = row.dataset.decoded || "";
        let formatted = decodedRaw;
        try {
          const parsed = JSON.parse(decodedRaw);
          formatted = JSON.stringify(parsed, null, 2);
        } catch (_) {
          formatted = decodedRaw;
        }
        decoded.textContent = formatted || "";
        overlay.hidden = false;
      });
    }

    function formatTimeParts(value, length) {
      return String(value).padStart(length, "0");
    }

    function formatSendTime(msValue) {
      if (msValue === undefined || msValue === null || msValue === "") {
        return "-";
      }
      const msNumber = Number(msValue);
      if (!Number.isFinite(msNumber)) {
        return "-";
      }
      const date = new Date(msNumber);
      if (Number.isNaN(date.getTime())) {
        return "-";
      }
      return (
        `${formatTimeParts(date.getHours(), 2)}:` +
        `${formatTimeParts(date.getMinutes(), 2)}:` +
        `${formatTimeParts(date.getSeconds(), 2)}.` +
        `${formatTimeParts(date.getMilliseconds(), 3)}`
      );
    }

    function formatReplaySendTimes(section) {
      if (!section) return;
      section.querySelectorAll("tr[data-send-time-ms]").forEach((row) => {
        const cell = row.querySelector(".send-time-cell");
        if (!cell) return;
        cell.textContent = formatSendTime(row.dataset.sendTimeMs || "");
      });
    }

    function initReplayStream() {
      const container = document.querySelector("[data-replay-stream]");
      if (!container) return;
      const token = container.dataset.replayToken || "";
      const statusUrl = container.dataset.replayStatusUrl || "";
      if (!token || !statusUrl) return;

      const statusBlock = container.querySelector("[data-replay-status]");
      const progressFill = container.querySelector("[data-replay-progress]");
      const progressText = container.querySelector("[data-replay-progress-text]");
      const metaTarget = container.querySelector("[data-replay-target]");
      const etaText = container.querySelector("[data-replay-eta]");
      const logBody = document.querySelector("[data-replay-log-body]");
      const stopButton = document.querySelector("[data-stop-replay]");
      const resumeButton = document.querySelector("[data-resume-replay]");
      const restartButton = document.querySelector("[data-restart-replay]");
      let etaTimer = null;

      let received = 0;
      let done = false;

      const formatDuration = (ms) => {
        const totalSeconds = Math.max(0, Math.ceil(ms / 1000));
        const hours = Math.floor(totalSeconds / 3600);
        const minutes = Math.floor((totalSeconds % 3600) / 60);
        const seconds = totalSeconds % 60;
        if (hours > 0) {
          return `${hours}:${formatTimeParts(minutes, 2)}:${formatTimeParts(seconds, 2)}`;
        }
        return `${minutes}:${formatTimeParts(seconds, 2)}`;
      };

      const updateEta = (data) => {
        if (!etaText) return;
        if (etaTimer) {
          clearInterval(etaTimer);
          etaTimer = null;
        }
        if (data.status !== "running") {
          etaText.textContent = "ETA 0:00";
          return;
        }
        const delayMs = Number(data.delay_ms) || 0;
        const total = data.total || 0;
        const processed = (data.sent || 0) + (data.errors || 0);
        const remaining = Math.max(0, total - processed);
        if (!delayMs || remaining === 0) {
          etaText.textContent = "ETA 0:00";
          return;
        }
        const targetTime = Date.now() + remaining * delayMs;
        const render = () => {
          const remainingMs = targetTime - Date.now();
          etaText.textContent = `ETA ${formatDuration(remainingMs)}`;
        };
        render();
        etaTimer = window.setInterval(render, 250);
      };

      const updateStatus = (data) => {
        const total = data.total || 0;
        const sent = data.sent || 0;
        const errors = data.errors || 0;
        const processed = sent + errors;
        const percent = total ? Math.min(100, Math.round((processed / total) * 100)) : 0;

        if (progressFill) {
          progressFill.style.width = `${percent}%`;
        }
        if (progressText) {
          progressText.textContent = `Sent ${sent} of ${total} · Errors ${errors}`;
        }
        if (metaTarget) {
          metaTarget.textContent = `Target ${data.host || "?"}:${data.port || "?"} · Delay ${data.delay_ms || 0} ms`;
        }
        if (statusBlock) {
          statusBlock.classList.remove("info", "success", "error");
          if (data.status === "done") {
            statusBlock.classList.add(errors === 0 ? "success" : "error");
            statusBlock.textContent = `Replay done. Sent ${sent}, errors ${errors}.`;
          } else if (data.status === "stopped") {
            statusBlock.classList.add("error");
            statusBlock.textContent = `Replay stopped. Sent ${sent}, errors ${errors}.`;
          } else {
            statusBlock.classList.add("info");
            statusBlock.textContent = `Replaying... Sent ${sent} of ${total}.`;
          }
        }

        if (stopButton) {
          const isRunning = data.status === "running";
          stopButton.disabled = !isRunning;
          stopButton.classList.toggle("is-hidden", !isRunning);
        }
        if (resumeButton) {
          const isStopped = data.status === "stopped";
          resumeButton.disabled = !isStopped;
          resumeButton.classList.toggle("is-hidden", !isStopped);
        }
        if (restartButton) {
          const showRestart = data.status === "stopped" || data.status === "done";
          restartButton.disabled = !showRestart;
          restartButton.classList.toggle("is-hidden", !showRestart);
        }
        updateEta(data);
      };

      const appendLines = (lines) => {
        if (!logBody || !Array.isArray(lines) || lines.length === 0) return;
        const fragment = document.createDocumentFragment();
        lines.forEach((line) => {
          const row = document.createElement("tr");
          row.className = line.css || "";
          row.dataset.index = line.index ?? "";
          row.dataset.status = line.status ?? "";
          row.dataset.sendTimeMs = line.send_time_ms ?? "";
          row.dataset.gateway = line.gateway ?? "";
          row.dataset.fcnt = line.fcnt ?? "";
          row.dataset.freq = line.freq ?? "";
          row.dataset.size = line.size ?? "";
          row.dataset.message = line.message ?? "";

          const cells = [
            { value: line.index },
            { value: line.status },
            { value: formatSendTime(line.send_time_ms), className: "send-time-cell" },
            { value: line.gateway },
            { value: line.fcnt },
            { value: line.freq },
            { value: line.size },
            { value: line.message },
          ];
          cells.forEach((cellData) => {
            const cell = document.createElement("td");
            if (cellData.className) {
              cell.className = cellData.className;
            }
            const value = cellData.value;
            cell.textContent = value === undefined || value === null || value === "" ? "-" : value;
            row.appendChild(cell);
          });
          fragment.appendChild(row);
        });
        logBody.appendChild(fragment);
      };

      const poll = () => {
        if (done) return;
        const url = new URL(statusUrl, window.location.origin);
        url.searchParams.set("token", token);
        url.searchParams.set("since", String(received));
        fetch(url.toString(), { cache: "no-store" })
          .then((response) => {
            if (!response.ok) {
              throw new Error("Replay status request failed.");
            }
            return response.json();
          })
          .then((data) => {
            if (data.error) {
              throw new Error(data.error);
            }
            if (Array.isArray(data.lines)) {
              appendLines(data.lines);
            }
            if (typeof data.count === "number") {
              received = data.count;
            }
            updateStatus(data);
            if (data.status === "done" || data.status === "stopped") {
              done = true;
              return;
            }
            window.setTimeout(poll, 600);
          })
          .catch(() => {
            if (!done) {
              window.setTimeout(poll, 1200);
            }
          });
      };

      poll();
    }

    document.addEventListener("DOMContentLoaded", () => {
      const logSection = document.querySelector("[data-log-section]");
      formatReplaySendTimes(logSection);
      if (logSection && !logSection.dataset.liveReplay) {
        initSortableTable(logSection);
        initTruncation(logSection);
      }
      initSortableTable(document.querySelector("[data-decode-section]"));
      initTruncation(document.querySelector("[data-decode-section]"));
      initDetailOverlay(document.querySelector("[data-decode-section]"));
      initReplayStream();
      document.querySelectorAll("[data-toggle-visibility]").forEach((button) => {
        button.addEventListener("click", () => {
          const targetId = button.dataset.toggleVisibility;
          const input = document.getElementById(targetId);
          if (!input) return;
          const isHidden = input.type === "password";
          input.type = isHidden ? "text" : "password";
          button.setAttribute("aria-pressed", isHidden ? "true" : "false");
          button.title = isHidden ? "Hide key" : "Show key";
        });
      });
      const drop = document.querySelector("[data-file-drop]");
      const form = drop?.closest("form");
      const overlay = document.querySelector("[data-loading-overlay]");
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
          }
        };
        const autoScan = () => {
          if (!input.files || input.files.length === 0) {
            return;
          }
          const scanUrl = form?.dataset.scanUrl;
          if (form && scanUrl) {
            form.action = scanUrl;
            form.submit();
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
              autoScan();
            }
            drop.classList.remove("dragover");
          })
        );

        input.addEventListener("change", () => {
          updateLabel();
          autoScan();
        });
        updateLabel();
      }

      if (overlay) {
        document.querySelectorAll("form").forEach((formEl) => {
          formEl.addEventListener("submit", (event) => {
            const submitter = event.submitter;
            if (submitter && submitter.dataset.showLoader === "true") {
              overlay.hidden = false;
            }
          });
        });
      }

      const decodeOverlay = document.querySelector("[data-decode-overlay]");
      if (decodeOverlay) {
        document.querySelectorAll("form").forEach((formEl) => {
          formEl.addEventListener("submit", (event) => {
            const submitter = event.submitter;
            if (submitter && submitter.dataset.showDecodeLoader === "true") {
              decodeOverlay.hidden = false;
            }
          });
        });
      }

      const scanOverlay = document.querySelector("[data-scan-overlay]");
      if (scanOverlay) {
        const closeBtn = scanOverlay.querySelector("[data-scan-close]");
        const close = () => {
          scanOverlay.hidden = true;
        };
        closeBtn?.addEventListener("click", close);
        scanOverlay.addEventListener("click", (event) => {
          if (event.target === scanOverlay) {
            close();
          }
        });
      }

      const deleteForm = document.querySelector("[data-delete-form]");
      if (deleteForm) {
        const deleteInput = deleteForm.querySelector("[data-delete-input]");
        document.querySelectorAll("[data-delete-devaddr]").forEach((button) => {
          button.addEventListener("click", () => {
            const devaddr = button.dataset.deleteDevaddr || "";
            if (!devaddr) return;
            if (!confirm(`Remove device ${devaddr}?`)) {
              return;
            }
            if (deleteInput) {
              deleteInput.value = devaddr;
            }
            deleteForm.submit();
          });
        });
      }

      const decoderDeleteForm = document.querySelector("[data-decoder-delete-form]");
      if (decoderDeleteForm) {
        const decoderInput = decoderDeleteForm.querySelector("[data-decoder-delete-input]");
        document.querySelectorAll("[data-delete-decoder]").forEach((button) => {
          button.addEventListener("click", () => {
            const decoderId = button.dataset.deleteDecoder || "";
            if (!decoderId) return;
            if (!confirm("Remove this decoder?")) {
              return;
            }
            if (decoderInput) {
              decoderInput.value = decoderId;
            }
            decoderDeleteForm.submit();
          });
        });
      }

      const fileDeleteForm = document.querySelector("[data-file-delete-form]");
      if (fileDeleteForm) {
        const fileInput = fileDeleteForm.querySelector("[data-file-delete-input]");
        document.querySelectorAll("[data-delete-file]").forEach((button) => {
          button.addEventListener("click", () => {
            const fileId = button.dataset.deleteFile || "";
            if (!fileId) return;
            if (!confirm("Remove this log file?")) {
              return;
            }
            if (fileInput) {
              fileInput.value = fileId;
            }
            fileDeleteForm.submit();
          });
        });
      }

      const menuToggle = document.querySelector("[data-menu-toggle]");
      const menuPanel = document.querySelector("[data-menu-panel]");
      if (menuToggle && menuPanel) {
        const closeMenu = () => {
          menuPanel.hidden = true;
          menuToggle.classList.remove("open");
          menuToggle.setAttribute("aria-expanded", "false");
        };
        const openMenu = () => {
          menuPanel.hidden = false;
          menuToggle.classList.add("open");
          menuToggle.setAttribute("aria-expanded", "true");
        };
        menuToggle.addEventListener("click", () => {
          if (menuPanel.hidden) {
            openMenu();
          } else {
            closeMenu();
          }
        });
        menuPanel.querySelectorAll("a").forEach((link) => {
          link.addEventListener("click", () => closeMenu());
        });
        document.addEventListener("click", (event) => {
          if (menuPanel.hidden) return;
          if (menuPanel.contains(event.target) || menuToggle.contains(event.target)) {
            return;
          }
          closeMenu();
        });
      }
    });
  </script>
"""

NAV_HTML = """
  <header class="top-bar">
    <div class="brand">
      <img src="{{ logo_url }}" alt="Smart Parks logo">
      <div>
        <div class="brand-title">OpenCollar LP0 Replay tool</div>
        <div class="brand-subtitle">Smart Parks</div>
      </div>
    </div>
    <button type="button" class="menu-toggle" data-menu-toggle aria-expanded="false" aria-controls="site-menu">
      <span class="bars" aria-hidden="true">
        <span class="bar"></span>
        <span class="bar"></span>
        <span class="bar"></span>
      </span>
      <span class="menu-label" aria-hidden="true">Menu</span>
    </button>
  </header>
  <nav id="site-menu" class="menu-panel" data-menu-panel hidden>
    <a class="menu-link {% if active_page == 'start' %}active{% endif %}" href="{{ start_url }}">Start</a>
    <a class="menu-link {% if active_page == 'devices' %}active{% endif %}" href="{{ devices_url }}">Devices</a>
    <a class="menu-link {% if active_page == 'files' %}active{% endif %}" href="{{ files_url }}">Files</a>
    <a class="menu-link {% if active_page == 'decoders' %}active{% endif %}" href="{{ decoders_url }}">Decoders</a>
    <a class="menu-link {% if active_page == 'integrations' %}active{% endif %}" href="{{ integrations_url }}">Integrations</a>
    <a class="menu-link {% if active_page == 'about' %}active{% endif %}" href="{{ about_url }}">About</a>
  </nav>
"""

HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>OpenCollar LP0 Replay tool</title>
  <link rel="icon" type="image/x-icon" href="{{ favicon_url }}">
  {{ style_block|safe }}
</head>
<body>
  <div class="outer-column">
    {{ nav_html|safe }}

    <div class="card">
      <h1>Start</h1>
      <p class="subtitle">Upload a log file or pick a stored log file to scan and continue.</p>

      <form method="POST" action="{{ scan_url }}" enctype="multipart/form-data" data-scan-url="{{ scan_url }}">
        <div>
          <label for="logfile">Logfile</label>
          <div class="logfile-options">
            <div class="logfile-option">
              <h3>Upload a log file</h3>
              <input id="logfile" type="file" name="logfile" style="display: none;" aria-hidden="true">
              <div class="file-drop" data-file-drop>
                <div class="file-text">
                  <strong>Click to choose or drag & drop</strong>
                  <div class="file-selected" data-file-selected>{{ selected_filename or "No file selected" }}</div>
                  <div class="hint">Upload a JSON Lines file you captured earlier.</div>
                </div>
              </div>
            </div>
            <div class="logfile-option">
              <h3>Stored log file</h3>
              <div class="hint">Pick a previously uploaded log file.</div>
              <select id="stored_log_id" name="stored_log_id">
                <option value="">Select a stored logfile...</option>
                {% for log in stored_logs %}
                <option value="{{ log.id }}" {% if log.id == selected_stored_id %}selected{% endif %}>{{ log.filename }} ({{ log.uploaded_at }})</option>
                {% endfor %}
              </select>
            </div>
          </div>
        </div>

        <div class="form-actions">
          <button type="submit">Scan logfile</button>
        </div>

        {% if result_lines %}
        <div class="result {{ result_class }}">
          {% for line in result_lines %}
          <div>{{ line }}</div>
          {% endfor %}
        </div>
        {% endif %}
      </form>

      {% if scan_token %}
      <div class="next-steps">
        <h2>Next steps</h2>
        <div class="action-grid">
          <a class="primary-button" href="{{ decode_url }}?scan_token={{ scan_token }}">Decrypt &amp; decode</a>
          <a class="secondary-button" href="{{ replay_page_url }}?scan_token={{ scan_token }}">Replay</a>
        </div>
      </div>
      {% endif %}
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

REPLAY_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Replay LoRaWAN Log</title>
  <link rel="icon" type="image/x-icon" href="{{ favicon_url }}">
  {{ style_block|safe }}
</head>
<body>
  <div class="outer-column">
    {{ nav_html|safe }}

    <div class="card">
      <div class="card-header">
        <div>
          <h1>Replay</h1>
          <p class="subtitle">Replay uplinks from <strong>{{ selected_filename }}</strong> to your UDP forwarder.</p>
        </div>
        <a class="secondary-button" href="{{ back_url }}">Back</a>
      </div>

      {% if summary_lines %}
      <div class="result {{ summary_class }}">
        {% for line in summary_lines %}
        <div>{{ line }}</div>
        {% endfor %}
      </div>
      {% endif %}

      {% if result_lines %}
      <div class="result {{ result_class }}">
        {% for line in result_lines %}
        <div>{{ line }}</div>
        {% endfor %}
      </div>
      {% endif %}

      <div class="section-divider"></div>

      <form method="POST" action="{{ replay_url }}">
        <div>
          <label for="host">LoRaWAN server host</label>
          <input id="host" name="host" type="text" value="{{ form_values.host }}" {% if replay_token and replay_status == "running" %}disabled{% endif %}>
        </div>
        <div>
          <label for="port">UDP port</label>
          <input id="port" name="port" type="number" value="{{ form_values.port }}" {% if replay_token and replay_status == "running" %}disabled{% endif %}>
          <div class="hint">The default Semtech UDP port is 1700.</div>
        </div>
        <div>
          <label for="delay_ms">Delay between packets (ms)</label>
          <input id="delay_ms" name="delay_ms" type="number" min="0" step="1" value="{{ form_values.delay_ms }}" {% if replay_token and replay_status == "running" %}disabled{% endif %}>
          <div class="hint">Default is 500 milliseconds.</div>
        </div>
        {% if scan_token %}
        <input type="hidden" name="scan_token" value="{{ scan_token }}">
        {% endif %}
        {% if replay_token %}
        <input type="hidden" name="replay_token" value="{{ replay_token }}">
        {% endif %}
        <div class="form-actions">
          {% if replay_token %}
          <button type="submit" class="stop-replay-button{% if replay_status != "running" %} is-hidden{% endif %}"
                  data-stop-replay formaction="{{ replay_stop_url }}"
                  {% if replay_status != "running" %}disabled{% endif %}>
            Stop Replay
          </button>
          <button type="submit" class="resume-replay-button{% if replay_status != "stopped" %} is-hidden{% endif %}"
                  data-resume-replay formaction="{{ replay_resume_url }}"
                  {% if replay_status != "stopped" %}disabled{% endif %}>
            Resume Replay
          </button>
          <button type="submit" class="restart-replay-button{% if replay_status not in ["stopped", "done"] %} is-hidden{% endif %}"
                  data-restart-replay formaction="{{ replay_url }}"
                  {% if replay_status not in ["stopped", "done"] %}disabled{% endif %}>
            Restart Replay
          </button>
          {% endif %}
          {% if not replay_token %}
          <button type="submit" class="start-replay-button" data-replay-start {% if not scan_token %}disabled{% endif %}>
            Start Replay
          </button>
          {% endif %}
        </div>
      </form>

      {% if replay_token %}
      <div data-replay-stream data-replay-token="{{ replay_token }}" data-replay-status-url="{{ replay_status_url }}">
        <div class="result info replay-status" data-replay-status>Starting replay…</div>
        <div class="progress-track" aria-hidden="true">
          <div class="progress-fill" data-replay-progress></div>
        </div>
        <div class="progress-meta">
          <span data-replay-progress-text>Sent 0 of {{ replay_total }}</span>
          <span data-replay-target>Target -</span>
          <span data-replay-eta>ETA -</span>
        </div>
      </div>
      {% endif %}
    </div>

    {% if log_lines or replay_token %}
    <div class="log-wrapper" data-log-section {% if replay_token %}data-live-replay="true"{% endif %}>
      <details class="log-block" open>
        <summary>Replay log</summary>
        {% if not replay_token %}
        <div class="log-controls">
          <label>
            Rows to display:
            <select data-table-limit>
              <option value="20">20</option>
              <option value="50">50</option>
              <option value="100">100</option>
              <option value="all">All</option>
            </select>
          </label>
        </div>
        {% endif %}
        <div style="overflow-x: auto;">
          <table class="log-table" {% if not replay_token %}data-sortable-table data-numeric-keys="index,sendTimeMs,fcnt,freq,size"{% endif %}>
            <thead>
              <tr>
                {% if replay_token %}
                <th>#</th>
                <th>Status</th>
                <th>Sent at</th>
                <th>Gateway EUI</th>
                <th>FCnt</th>
                <th>Frequency</th>
                <th>Size</th>
                <th>Message</th>
                {% else %}
                <th><button type="button" data-sort-key="index">#</button></th>
                <th><button type="button" data-sort-key="status">Status</button></th>
                <th><button type="button" data-sort-key="sendTimeMs">Sent at</button></th>
                <th><button type="button" data-sort-key="gateway">Gateway EUI</button></th>
                <th><button type="button" data-sort-key="fcnt">FCnt</button></th>
                <th><button type="button" data-sort-key="freq">Frequency</button></th>
                <th><button type="button" data-sort-key="size">Size</button></th>
                <th><button type="button" data-sort-key="message">Message</button></th>
                {% endif %}
              </tr>
            </thead>
            <tbody data-replay-log-body>
              {% for log_line in log_lines %}
              <tr class="{{ log_line.css }}"
                  data-index="{{ log_line.index }}"
                  data-status="{{ log_line.status }}"
                  data-send-time-ms="{{ log_line.send_time_ms or '' }}"
                  data-gateway="{{ log_line.gateway or '' }}"
                  data-fcnt="{{ log_line.fcnt or '' }}"
                  data-freq="{{ log_line.freq or '' }}"
                  data-size="{{ log_line.size or '' }}"
                  data-message="{{ (log_line.message or '') | e }}">
                <td>{{ log_line.index }}</td>
                <td>{{ log_line.status }}</td>
                <td class="send-time-cell">-</td>
                <td>{{ log_line.gateway or "-" }}</td>
                <td>{{ log_line.fcnt or "-" }}</td>
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

    <p class="brand-note">
      A Smart Parks tool to Protect Wildlife with Passion and Technology.
      <a href="https://www.smartparks.org" target="_blank" rel="noopener">www.smartparks.org</a>
    </p>
  </div>
  <div class="loading-overlay" data-loading-overlay hidden>
    <div class="loading-card">
      <div class="spinner" aria-hidden="true"></div>
      <div>Replaying uplinks…</div>
    </div>
  </div>
  {{ script_block|safe }}
</body>
</html>
"""

SIMPLE_PAGE_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{{ page_title }}</title>
  <link rel="icon" type="image/x-icon" href="{{ favicon_url }}">
  {{ style_block|safe }}
</head>
<body>
  <div class="outer-column">
    {{ nav_html|safe }}

    <div class="card">
      <div class="card-header">
        <div>
          <h1>{{ title }}</h1>
          <p class="subtitle">{{ subtitle }}</p>
        </div>
        <a class="secondary-button" href="{{ back_url }}">Back</a>
      </div>
      {{ body_html|safe }}
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

DECODE_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Decrypt & Decode LoRaWAN Log</title>
  <link rel="icon" type="image/x-icon" href="{{ favicon_url }}">
  {{ style_block|safe }}
</head>
<body>
  <div class="outer-column">
    {{ nav_html|safe }}

    <div class="card">
      <div class="card-header">
        <div>
          <h1>Decrypt &amp; Decode</h1>
          <p class="subtitle">Decrypt uplinks from <strong>{{ selected_filename }}</strong> and decode them with your payload decoder.</p>
        </div>
        <a class="secondary-button" href="{{ back_url }}">Back</a>
      </div>

      {% if summary_lines %}
      <div class="result {{ result_class }}">
        {% for line in summary_lines %}
        <div>{{ line }}</div>
        {% endfor %}
      </div>
      {% endif %}

      <div class="section-divider"></div>

      <div class="field-group">
        <div class="field-header">
          <label>Device session keys</label>
        </div>
        <div class="hint">Review the devices discovered in this logfile and edit credentials on the Device session keys page.</div>
        <div class="key-grid">
          {% for devaddr in devaddrs %}
          <div class="field-group">
            <div class="field-header">
              <label>{{ credentials.get(devaddr, {}).get('name', 'Device') }} — {{ devaddr }}
                {% if devaddr in missing_keys %}
                <span class="tag">Missing</span>
                {% endif %}
              </label>
            </div>
            <div class="hint">Session keys stored: {% if devaddr in missing_keys %}no{% else %}yes{% endif %}</div>
          </div>
          {% endfor %}
        </div>
        <div class="form-actions">
          <a class="secondary-button" href="{{ keys_url }}?scan_token={{ scan_token }}">Manage Devices</a>
        </div>
      </div>

      {% if missing_keys %}
      <div class="section-divider"></div>

      <div class="field-group missing-keys-block">
        <div class="field-header">
          <label>Add missing devices</label>
        </div>
        <div class="hint">Add session keys for missing DevAddr entries so decoding can continue.</div>
        <div class="hint-divider" aria-hidden="true"></div>
        {% for devaddr in missing_keys %}
        <form method="POST" action="{{ decode_url }}">
          <input type="hidden" name="scan_token" value="{{ scan_token }}">
          <input type="hidden" name="action" value="add_device">
          <input type="hidden" name="decoder_id" value="{{ selected_decoder }}">
          <div class="field-group">
            <div class="field-header">
              <label>DevAddr {{ devaddr }}</label>
            </div>
            <div class="key-grid add-device-grid">
              <div>
                <label for="new_devaddr_{{ devaddr }}">DevAddr (hex)</label>
                <input id="new_devaddr_{{ devaddr }}" name="new_devaddr" type="text" value="{{ devaddr }}" readonly>
              </div>
              <div>
                <label for="new_name_{{ devaddr }}">Device name (optional)</label>
                <input id="new_name_{{ devaddr }}" name="new_name" type="text" placeholder="Wildlife collar 17">
              </div>
              <div>
                <label for="new_nwk_{{ devaddr }}">NwkSKey (hex)</label>
                <input id="new_nwk_{{ devaddr }}" name="new_nwk" type="password" placeholder="000102030405060708090A0B0C0D0E0F" pattern="[0-9A-Fa-f]{32}" minlength="32" maxlength="32" title="32 hex characters" autocomplete="off" spellcheck="false">
              </div>
              <div>
                <label for="new_app_{{ devaddr }}">AppSKey (hex)</label>
                <input id="new_app_{{ devaddr }}" name="new_app" type="password" placeholder="F0E0D0C0B0A090807060504030201000" pattern="[0-9A-Fa-f]{32}" minlength="32" maxlength="32" title="32 hex characters" autocomplete="off" spellcheck="false">
              </div>
            </div>
            <div class="form-actions">
              <button type="submit">Add device</button>
            </div>
          </div>
        </form>
        {% endfor %}
      </div>

      <div class="section-divider"></div>
      {% else %}
      <div class="section-divider"></div>
      {% endif %}

      <form method="POST" action="{{ decode_url }}">
        <input type="hidden" name="scan_token" value="{{ scan_token }}">
        <input type="hidden" name="action" value="decode">
        <div>
          <label for="decoder_id">Payload decoder</label>
          <select id="decoder_id" name="decoder_id" required>
            {% for decoder in decoders %}
            <option value="{{ decoder.id }}" {% if decoder.id == selected_decoder %}selected{% endif %}>{{ decoder.label }}</option>
            {% endfor %}
          </select>
          <div class="hint">Select the decoder and press Decode to process all decrypted payloads.</div>
          <div class="form-actions">
            <a class="secondary-button" href="{{ decoders_url }}">Manage Decoders</a>
          </div>
        </div>
        <div class="form-actions">
          <button type="submit" class="start-replay-button" {% if missing_keys %}disabled{% endif %} data-show-decode-loader="true">Decode</button>
        </div>
        {% if missing_keys %}
        <div class="result error">Missing keys for {{ missing_keys|length }} DevAddr(s). Save keys before decoding.</div>
        {% endif %}
      </form>

      {% if decode_results %}
      <div class="section-divider"></div>
      <div class="log-wrapper" data-decode-section>
        <details class="log-block" open>
          <summary>Decoded payloads</summary>
          <div class="log-controls">
            <label>
              Rows to display:
              <select data-table-limit>
                <option value="20">20</option>
                <option value="50">50</option>
                <option value="100">100</option>
                <option value="all">All</option>
              </select>
            </label>
          </div>
          <div style="overflow-x: auto;">
            <table class="log-table" data-sortable-table data-numeric-keys="index,fcnt,fport">
              <thead>
                <tr>
                  <th><button type="button" data-sort-key="index">#</button></th>
                  <th><button type="button" data-sort-key="status">Status</button></th>
                  <th><button type="button" data-sort-key="devaddr">DevAddr</button></th>
                  <th><button type="button" data-sort-key="fcnt">FCnt</button></th>
                  <th><button type="button" data-sort-key="fport">FPort</button></th>
                  <th><button type="button" data-sort-key="time">Time</button></th>
                  <th>Payload</th>
                  <th>Decoded</th>
                </tr>
              </thead>
              <tbody>
                {% for row in decode_results %}
                <tr class="{{ row.css }}"
                    data-index="{{ row.index }}"
                    data-status="{{ row.status }}"
                    data-devaddr="{{ row.devaddr }}"
                    data-fcnt="{{ row.fcnt }}"
                    data-fport="{{ row.fport }}"
                    data-time="{{ row.time }}"
                    data-payload="{{ row.payload_hex | e }}"
                    data-decoded="{{ row.decoded_preview | e }}">
                  <td>{{ row.index }}</td>
                  <td>{{ row.status }}</td>
                  <td>{{ row.devaddr }}</td>
                  <td>{{ row.fcnt }}</td>
                  <td>{{ row.fport }}</td>
                  <td>{{ row.time }}</td>
                  <td>
                    <button type="button" class="cell-action" data-detail-trigger>
                      Payload ({{ row.payload_hex|length }} bytes)
                    </button>
                  </td>
                  <td>
                    <button type="button" class="cell-action" data-detail-trigger>
                      Decoded view
                    </button>
                  </td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
        </details>
      </div>
      <div class="table-actions">
        <a class="secondary-button" href="{{ export_csv_url }}">Export CSV</a>
        <a class="secondary-button" href="{{ export_json_url }}">Export JSON</a>
      </div>
      {% endif %}
    </div>

    <div class="detail-overlay" data-detail-overlay hidden>
      <div class="detail-card">
        <h2 data-detail-title>Packet details</h2>
        <div class="detail-grid" data-detail-meta></div>
        <div class="detail-collapsible">
          <details open>
            <summary>Payload</summary>
            <div class="detail-block"><pre data-detail-payload></pre></div>
          </details>
        </div>
        <div class="detail-collapsible">
          <details open>
            <summary>Decoded (JSON)</summary>
            <div class="detail-block"><pre data-detail-decoded></pre></div>
          </details>
        </div>
        <div class="detail-actions">
          <button type="button" data-detail-close>Close</button>
        </div>
      </div>
    </div>
    <div class="loading-overlay" data-decode-overlay hidden>
      <div class="loading-card">
        <div class="progress-bar" aria-hidden="true"></div>
        <div>Decoding payloads…</div>
      </div>
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

DEVICE_KEYS_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Device Session Keys</title>
  <link rel="icon" type="image/x-icon" href="{{ favicon_url }}">
  {{ style_block|safe }}
</head>
<body>
  <div class="outer-column">
    {{ nav_html|safe }}

    <div class="card">
      <div class="card-header">
        <div>
          <h1>Device Session Keys</h1>
          <p class="subtitle">Store DevAddr, optional names, and ABP session keys for decoding.</p>
        </div>
        <a class="secondary-button" href="{{ back_url }}">Back</a>
      </div>

      {% if summary_lines %}
      <div class="result {{ result_class }}">
        {% for line in summary_lines %}
        <div>{{ line }}</div>
        {% endfor %}
      </div>
      {% endif %}

      <form method="POST" action="{{ keys_url }}" data-delete-form>
        {% if scan_token %}
        <input type="hidden" name="scan_token" value="{{ scan_token }}">
        {% endif %}
        <input type="hidden" name="action" value="delete_device">
        <input type="hidden" name="delete_devaddr" value="" data-delete-input>
      </form>

      <form method="POST" action="{{ keys_url }}">
        {% if scan_token %}
        <input type="hidden" name="scan_token" value="{{ scan_token }}">
        {% endif %}
        <input type="hidden" name="action" value="save_keys">
        <div class="field-group">
          <div class="field-header">
            <label>Known devices</label>
          </div>
          <div class="hint">Update keys or friendly names for devices already stored.</div>
          <div class="device-rows">
            {% for devaddr in known_devaddrs %}
            <div class="device-row">
              <div class="field-header">
                <label>DevAddr {{ devaddr }}</label>
              </div>
              <div class="key-grid device-grid">
                <div>
                  <label for="name_{{ devaddr }}">Device name</label>
                  <input id="name_{{ devaddr }}" name="name_{{ devaddr }}" type="text" value="{{ credentials.get(devaddr, {}).get('name', '') }}">
                </div>
                <div>
                  <label for="nwk_{{ devaddr }}">NwkSKey</label>
                  <div class="field-controls key-controls">
                    <input class="input-with-actions key-input" id="nwk_{{ devaddr }}" name="nwk_{{ devaddr }}" type="password" value="{{ credentials.get(devaddr, {}).get('nwk_skey', '') }}" pattern="[0-9A-Fa-f]{32}" minlength="32" maxlength="32" title="32 hex characters" autocomplete="off" spellcheck="false">
                    <button type="button" class="toggle-visibility" data-toggle-visibility="nwk_{{ devaddr }}" aria-pressed="false" title="Show key">👁</button>
                  </div>
                </div>
                <div>
                  <label for="app_{{ devaddr }}">AppSKey</label>
                  <div class="field-controls key-controls">
                    <input class="input-with-actions key-input" id="app_{{ devaddr }}" name="app_{{ devaddr }}" type="password" value="{{ credentials.get(devaddr, {}).get('app_skey', '') }}" pattern="[0-9A-Fa-f]{32}" minlength="32" maxlength="32" title="32 hex characters" autocomplete="off" spellcheck="false">
                    <button type="button" class="toggle-visibility" data-toggle-visibility="app_{{ devaddr }}" aria-pressed="false" title="Show key">👁</button>
                  </div>
                </div>
                <div class="remove-cell">
                  <button type="button" class="danger-button" data-delete-devaddr="{{ devaddr }}" title="Remove device" aria-label="Remove device">
                    🗑
                  </button>
                </div>
              </div>
            </div>
            {% endfor %}
          </div>
        </div>
        <div class="form-actions">
          <button type="submit">Save updates</button>
        </div>
      </form>

      <div class="section-divider"></div>

      <form method="POST" action="{{ keys_url }}">
        {% if scan_token %}
        <input type="hidden" name="scan_token" value="{{ scan_token }}">
        {% endif %}
        <input type="hidden" name="action" value="add_device">
        <div class="field-group">
          <div class="field-header">
            <label>Add a new device</label>
          </div>
          <div class="hint">Add a DevAddr upfront so it is ready for future logfiles.</div>
          <div class="key-grid add-device-grid">
            <div>
              <label for="new_devaddr">DevAddr (hex)</label>
              <input id="new_devaddr" name="new_devaddr" type="text" placeholder="26011BDA">
            </div>
            <div>
              <label for="new_name">Device name (optional)</label>
              <input id="new_name" name="new_name" type="text" placeholder="Wildlife collar 17">
            </div>
            <div>
              <label for="new_nwk">NwkSKey (hex)</label>
              <input id="new_nwk" name="new_nwk" type="password" placeholder="000102030405060708090A0B0C0D0E0F" pattern="[0-9A-Fa-f]{32}" minlength="32" maxlength="32" title="32 hex characters" autocomplete="off" spellcheck="false">
            </div>
            <div>
              <label for="new_app">AppSKey (hex)</label>
              <input id="new_app" name="new_app" type="password" placeholder="F0E0D0C0B0A090807060504030201000" pattern="[0-9A-Fa-f]{32}" minlength="32" maxlength="32" title="32 hex characters" autocomplete="off" spellcheck="false">
            </div>
          </div>
        </div>
        <div class="form-actions">
          <button type="submit">Add device</button>
        </div>
      </form>
    </div>

    <p class="brand-note">
      A Smart Parks tool to Protect Wildlife with Passion and Technology.
      <a href="https://www.smartparks.org" target="_blank" rel="noopener">www.smartparks.org</a>
    </p>
  </div>
  {% if scan_summary_lines %}
  <div class="scan-overlay" data-scan-overlay>
    <div class="scan-card">
      <h2>Scan results{% if scan_filename %} — {{ scan_filename }}{% endif %}</h2>
      <div class="result success">
        {% for line in scan_summary_lines %}
        <div>{{ line }}</div>
        {% endfor %}
      </div>
      <div class="form-actions">
        <button type="button" data-scan-close>Close</button>
      </div>
    </div>
  </div>
  {% endif %}
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
    {{ nav_html|safe }}

    <div class="card">
      <div class="card-header">
        <div>
          <h1>Generate Test Logfile</h1>
          <p class="subtitle">Configure LoRaWAN ABP parameters and download a JSON Lines log.</p>
        </div>
        <a class="secondary-button" href="{{ files_url }}">Back to Files</a>
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
          <a class="secondary-button" href="{{ files_url }}">Back to Files</a>
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


def ensure_data_dirs():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(DECODER_DIR, exist_ok=True)
    os.makedirs(BUILTIN_DECODER_DIR, exist_ok=True)


def load_json_file(path, default):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError:
        return default


def save_json_file(path, data):
    ensure_data_dirs()
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    os.replace(tmp_path, path)


def list_stored_logs():
    entries = load_json_file(UPLOAD_INDEX_PATH, [])
    available = []
    for entry in entries:
        if os.path.exists(entry.get("path", "")):
            available.append(entry)
    return available


def get_stored_log_entry(log_id):
    for entry in list_stored_logs():
        if entry.get("id") == log_id:
            return entry
    return None


def store_uploaded_log(logfile):
    ensure_data_dirs()
    token = secrets.token_urlsafe(8)
    filename = secure_filename(logfile.filename or "log.jsonl") or "log.jsonl"
    stored_name = f"{token}_{filename}"
    path = os.path.join(UPLOAD_DIR, stored_name)
    logfile.save(path)
    entry = {
        "id": token,
        "filename": filename,
        "path": path,
        "uploaded_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    entries = load_json_file(UPLOAD_INDEX_PATH, [])
    entries.insert(0, entry)
    save_json_file(UPLOAD_INDEX_PATH, entries[:200])
    return entry


def delete_stored_log(log_id):
    entries = load_json_file(UPLOAD_INDEX_PATH, [])
    kept = []
    removed_path = None
    for entry in entries:
        if entry.get("id") == log_id:
            removed_path = entry.get("path")
        else:
            kept.append(entry)
    save_json_file(UPLOAD_INDEX_PATH, kept)
    if removed_path and os.path.exists(removed_path):
        os.remove(removed_path)
    return removed_path is not None


def scan_stored_log(log_id):
    entry = get_stored_log_entry(log_id)
    if not entry:
        raise ValueError("Log file not found.")
    with open(entry["path"], "rb") as handle:
        parsed, gateways, devaddrs, scan_errors = scan_logfile(handle)
    if scan_errors:
        preview = scan_errors[:10]
        error_lines = [
            "Logfile scan summary:",
            f"Uplinks (valid)={len(parsed)}",
            format_list("Gateway EUI", gateways),
            format_list("DevAddr (hex)", devaddrs),
            f"Validation errors={len(scan_errors)}.",
        ]
        error_lines.extend(preview)
        if len(scan_errors) > len(preview):
            error_lines.append(f"... (+{len(scan_errors) - len(preview)} more)")
        raise ValueError("\n".join(error_lines))
    if not parsed:
        raise ValueError("No valid uplinks found.")
    scan_token = store_scan_result(parsed, gateways, devaddrs, entry["filename"], entry["id"])
    return scan_token, entry


def load_credentials():
    return load_json_file(CREDENTIALS_PATH, {})


def save_credentials(credentials):
    save_json_file(CREDENTIALS_PATH, credentials)


def normalize_skey(value, label):
    cleaned = clean_hex(value).upper()
    if len(cleaned) != 32:
        raise ValueError(f"{label} must be 16 bytes (32 hex chars).")
    return cleaned


def normalize_devaddr(value):
    cleaned = clean_hex(value).upper()
    if len(cleaned) != 8:
        raise ValueError("DevAddr must be 4 bytes (8 hex chars).")
    return cleaned


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


def hex_to_bytes(value, label):
    cleaned = clean_hex(value)
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"{label} must be valid hex.") from exc
    if len(raw) != 16:
        raise ValueError(f"{label} must be 16 bytes (32 hex chars).")
    return raw


def parse_uplink(rxpk):
    data = rxpk.get("data")
    if not data:
        raise ValueError("Missing rxpk.data payload.")
    try:
        phy = base64.b64decode(data, validate=True)
    except binascii.Error as exc:
        raise ValueError("rxpk.data is not valid base64.") from exc
    if len(phy) < 12:
        raise ValueError("PHYPayload too short.")

    mhdr = phy[0]
    mtype = (mhdr >> 5) & 0x07
    if mtype not in (2, 4):
        raise ValueError("PHYPayload is not an uplink data frame.")

    mac_payload = phy[1:-4]
    if len(mac_payload) < 7:
        raise ValueError("MACPayload too short.")

    devaddr_le = mac_payload[0:4]
    devaddr = devaddr_le[::-1].hex().upper()
    fctrl = mac_payload[4]
    fcnt = int.from_bytes(mac_payload[5:7], "little")
    fopts_len = fctrl & 0x0F

    fhdr_len = 7 + fopts_len
    if len(mac_payload) < fhdr_len:
        raise ValueError("FHDR length mismatch.")

    fopts = mac_payload[7:7 + fopts_len]
    remaining = mac_payload[fhdr_len:]
    fport = None
    frm_payload = b""
    if remaining:
        fport = remaining[0]
        frm_payload = remaining[1:]

    return {
        "mhdr": mhdr,
        "mtype": mtype,
        "devaddr": devaddr,
        "devaddr_le": devaddr_le,
        "fctrl": fctrl,
        "fcnt": fcnt,
        "fopts": fopts,
        "fport": fport,
        "frm_payload": frm_payload,
    }


def lorawan_decrypt_payload(key, devaddr_le, fcnt, payload, direction=0):
    if not payload:
        return b""
    cipher = make_aes_cipher(key)
    out = bytearray()
    block_count = (len(payload) + 15) // 16
    for i in range(block_count):
        a_block = bytearray(16)
        a_block[0] = 0x01
        a_block[5] = direction & 0x01
        a_block[6:10] = devaddr_le
        a_block[10:14] = fcnt.to_bytes(4, "little")
        a_block[15] = i + 1
        s_block = cipher.encrypt(bytes(a_block))
        start = i * 16
        end = start + 16
        block = payload[start:end]
        for j, b in enumerate(block):
            out.append(b ^ s_block[j])
    return bytes(out)


def make_aes_cipher(key):
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise RuntimeError("PyCryptodome is required for LoRaWAN decryption.") from exc
    return AES.new(key, AES.MODE_ECB)


def extract_devaddr(rxpk):
    data = rxpk.get("data")
    if not data:
        raise ValueError("Missing rxpk.data payload.")
    try:
        payload = base64.b64decode(data, validate=True)
    except binascii.Error as exc:
        raise ValueError("rxpk.data is not valid base64.") from exc
    if len(payload) < 5:
        raise ValueError("PHYPayload too short to contain a DevAddr.")
    devaddr_le = payload[1:5]
    return devaddr_le[::-1].hex().upper()


def scan_logfile(stream):
    parsed = []
    gateways = set()
    devaddrs = set()
    errors = []

    for line_no, raw_line in enumerate(stream, start=1):
        if isinstance(raw_line, str):
            raw_line = raw_line.encode("utf-8")
        try:
            line = raw_line.decode("utf-8").strip()
        except UnicodeDecodeError:
            errors.append(f"Line {line_no}: invalid UTF-8 encoding.")
            continue

        if not line:
            continue

        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"Line {line_no}: JSON decode error ({exc}).")
            continue

        if not isinstance(rec, dict):
            errors.append(f"Line {line_no}: expected an object.")
            continue

        gateway_eui = rec.get("gatewayEui") or rec.get("gateway_eui")
        rxpk = rec.get("rxpk")
        if not gateway_eui or not isinstance(rxpk, dict):
            errors.append(f"Line {line_no}: missing gatewayEui or rxpk.")
            continue

        try:
            normalize_gateway_eui(gateway_eui)
        except ValueError as exc:
            errors.append(f"Line {line_no}: {exc}")
            continue

        try:
            devaddr = extract_devaddr(rxpk)
        except ValueError as exc:
            errors.append(f"Line {line_no}: {exc}")
            continue

        gateways.add(gateway_eui)
        devaddrs.add(devaddr)
        parsed.append({"gateway_eui": gateway_eui, "rxpk": rxpk})

    return parsed, sorted(gateways), sorted(devaddrs), errors


def prune_scan_cache(now=None):
    if not SCAN_CACHE:
        return
    now = time.time() if now is None else now
    expired = [token for token, entry in SCAN_CACHE.items() if now - entry["ts"] > SCAN_CACHE_TTL]
    for token in expired:
        del SCAN_CACHE[token]


def prune_decode_cache(now=None):
    if not DECODE_CACHE:
        return
    now = time.time() if now is None else now
    expired = [token for token, entry in DECODE_CACHE.items() if now - entry["ts"] > DECODE_CACHE_TTL]
    for token in expired:
        del DECODE_CACHE[token]


def prune_replay_cache(now=None):
    if not REPLAY_CACHE:
        return
    now = time.time() if now is None else now
    expired = [token for token, entry in REPLAY_CACHE.items() if now - entry["ts"] > REPLAY_CACHE_TTL]
    for token in expired:
        del REPLAY_CACHE[token]


def resolve_back_url(default_url):
    referrer = request.referrer or ""
    if not referrer:
        return default_url
    if referrer == request.url:
        return default_url
    parsed = urllib.parse.urlparse(referrer)
    host = urllib.parse.urlparse(request.host_url)
    if parsed.netloc and parsed.netloc != host.netloc:
        return default_url
    if parsed.scheme and parsed.scheme != host.scheme:
        return default_url
    blocked_paths = {
        "/scan",
        "/files/delete",
        "/replay/stop",
        "/replay/resume",
        "/replay/status",
    }
    if parsed.path in blocked_paths:
        return default_url
    return referrer


def store_replay_job(total, host, port, delay_ms, start_index=0, sent=0, errors=0, log_lines=None):
    prune_replay_cache()
    token = secrets.token_urlsafe(16)
    REPLAY_CACHE[token] = {
        "ts": time.time(),
        "status": "running",
        "total": total,
        "sent": sent,
        "errors": errors,
        "host": host,
        "port": port,
        "delay_ms": delay_ms,
        "start_index": start_index,
        "current_index": start_index,
        "log_lines": list(log_lines or []),
    }
    return token


def get_replay_job(token):
    prune_replay_cache()
    return REPLAY_CACHE.get(token)


def update_replay_job(token, **updates):
    with REPLAY_LOCK:
        entry = REPLAY_CACHE.get(token)
        if not entry:
            return
        entry.update(updates)
        entry["ts"] = time.time()


def append_replay_log(token, log_line, sent=None, errors=None, status=None):
    with REPLAY_LOCK:
        entry = REPLAY_CACHE.get(token)
        if not entry:
            return
        entry["log_lines"].append(log_line)
        if sent is not None:
            entry["sent"] = sent
        if errors is not None:
            entry["errors"] = errors
        if status is not None:
            entry["status"] = status
        entry["ts"] = time.time()


def store_scan_result(parsed, gateways, devaddrs, filename, stored_log_id=""):
    prune_scan_cache()
    token = secrets.token_urlsafe(16)
    SCAN_CACHE[token] = {
        "parsed": parsed,
        "gateways": gateways,
        "devaddrs": devaddrs,
        "filename": filename,
        "stored_log_id": stored_log_id,
        "ts": time.time(),
    }
    return token


def get_scan_result(token):
    prune_scan_cache()
    entry = SCAN_CACHE.get(token)
    if not entry:
        return None
    return entry["parsed"], entry["gateways"], entry["devaddrs"], entry["filename"], entry.get("stored_log_id", "")


def store_decode_result(rows):
    prune_decode_cache()
    token = secrets.token_urlsafe(16)
    DECODE_CACHE[token] = {"rows": rows, "ts": time.time()}
    return token


def get_decode_result(token):
    prune_decode_cache()
    entry = DECODE_CACHE.get(token)
    if not entry:
        return None
    return entry["rows"]


def format_list(label, items, limit=10):
    if not items:
        return f"{label}: none"
    if len(items) <= limit:
        return f"{label}: {', '.join(items)}"
    remaining = len(items) - limit
    preview = ", ".join(items[:limit])
    return f"{label}: {preview} (+{remaining} more)"


JS_DECODER_RUNNER = r"""
const fs = require("fs");
const vm = require("vm");

const path = process.argv[1];
const fport = parseInt(process.argv[2], 10) || 0;
const b64 = process.argv[3] || "";
const buf = Buffer.from(b64, "base64");
const bytes = Array.from(buf.values());

const code = fs.readFileSync(path, "utf8");
const sandbox = { console: console };
vm.createContext(sandbox);
vm.runInContext(code, sandbox);

let result;
if (typeof sandbox.Decoder === "function") {
  result = { data: sandbox.Decoder(bytes, fport) };
} else if (typeof sandbox.decodeUplink === "function") {
  result = sandbox.decodeUplink({ bytes: bytes, fPort: fport });
} else if (typeof sandbox.decode === "function") {
  result = sandbox.decode(bytes, fport);
} else {
  throw new Error("Decoder file must export decodeUplink(), Decoder(), or decode().");
}

process.stdout.write(JSON.stringify(result === undefined ? null : result));
"""


def list_decoders():
    ensure_data_dirs()
    decoders = [{"id": "raw", "label": "Raw payload (hex)", "source": "builtin"}]
    for filename in sorted(os.listdir(BUILTIN_DECODER_DIR)):
        if filename.lower().endswith(".js"):
            decoder_id = f"builtin:{filename}"
            decoders.append({"id": decoder_id, "label": filename, "source": "builtin"})
    for filename in sorted(os.listdir(DECODER_DIR)):
        if filename.lower().endswith(".js"):
            decoder_id = f"file:{filename}"
            decoders.append({"id": decoder_id, "label": filename, "source": "upload"})
    return decoders


def load_decoder(decoder_id):
    if decoder_id == "raw":
        def decode(payload, fport, devaddr, rxpk):
            return {"payload_hex": payload.hex().upper(), "fport": fport}

        return decode

    def load_js_decoder(path):
        if not os.path.exists(path):
            raise ValueError("Decoder file not found.")

        def decode(payload, fport, devaddr, rxpk):
            if fport is None:
                fport_value = 0
            else:
                fport_value = int(fport)
            b64_payload = base64.b64encode(payload).decode("ascii")
            try:
                result = subprocess.run(
                    ["node", "-e", JS_DECODER_RUNNER, path, str(fport_value), b64_payload],
                    capture_output=True,
                    text=True,
                    check=True,
                )
            except FileNotFoundError as exc:
                raise ValueError("Node.js is required to run JS decoders.") from exc
            except subprocess.CalledProcessError as exc:
                err = exc.stderr.strip() or "Unknown decoder error."
                raise ValueError(err) from exc
            output = result.stdout.strip()
            if not output:
                return None
            return json.loads(output)

        return decode

    if decoder_id.startswith("builtin:"):
        filename = decoder_id.split("builtin:", 1)[1]
        if ".." in filename or "/" in filename or "\\" in filename:
            raise ValueError("Invalid decoder selection.")
        path = os.path.join(BUILTIN_DECODER_DIR, filename)
        return load_js_decoder(path)

    if decoder_id.startswith("file:"):
        filename = decoder_id.split("file:", 1)[1]
        if ".." in filename or "/" in filename or "\\" in filename:
            raise ValueError("Invalid decoder selection.")
        path = os.path.join(DECODER_DIR, filename)
        return load_js_decoder(path)

    raise ValueError("Unknown decoder selection.")


def resolve_decoder_path(decoder_id):
    if decoder_id.startswith("builtin:"):
        filename = decoder_id.split(":", 1)[1]
        if ".." in filename or "/" in filename or "\\" in filename:
            raise ValueError("Invalid decoder selection.")
        return os.path.join(BUILTIN_DECODER_DIR, filename)
    if decoder_id.startswith("file:"):
        filename = decoder_id.split(":", 1)[1]
        if ".." in filename or "/" in filename or "\\" in filename:
            raise ValueError("Invalid decoder selection.")
        return os.path.join(DECODER_DIR, filename)
    raise ValueError("Unknown decoder selection.")


def nav_context(active_page, logo_url):
    context = {
        "active_page": active_page,
        "start_url": url_for("index"),
        "devices_url": url_for("device_keys"),
        "files_url": url_for("files_page"),
        "decoders_url": url_for("decoders_page"),
        "integrations_url": url_for("integrations_page"),
        "about_url": url_for("about_page"),
    }
    nav_html = render_template_string(NAV_HTML, logo_url=logo_url, **context)
    return {**context, "nav_html": nav_html}


def render_main_page(
    result_lines=None,
    result_class="",
    log_lines=None,
    form_values=None,
    scan_token="",
    selected_filename="",
    stored_logs=None,
    selected_stored_id="",
):
    values = {
        "host": "127.0.0.1",
        "port": "1700",
        "delay_ms": "500",
    }
    if form_values:
        values["host"] = form_values.get("host", values["host"])
        values["port"] = form_values.get("port", values["port"])
        values["delay_ms"] = form_values.get("delay_ms", values["delay_ms"])
    logo_url = url_for("static", filename="company_logo.png")
    return render_template_string(
        HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=logo_url,
        favicon_url=url_for("static", filename="favicon.ico"),
        replay_url=url_for("replay"),
        replay_page_url=url_for("replay"),
        scan_url=url_for("scan"),
        decode_url=url_for("decode"),
        form_values=values,
        result_lines=result_lines or [],
        result_class=result_class,
        log_lines=log_lines or [],
        scan_token=scan_token,
        selected_filename=selected_filename,
        stored_logs=stored_logs or [],
        selected_stored_id=selected_stored_id,
        **nav_context("start", logo_url),
    )


def render_replay_page(
    form_values=None,
    scan_token="",
    selected_filename="",
    summary_lines=None,
    summary_class="",
    result_lines=None,
    result_class="",
    log_lines=None,
    replay_token="",
    replay_total=0,
    replay_status="",
    back_url="",
):
    values = {
        "host": "127.0.0.1",
        "port": "1700",
        "delay_ms": "500",
    }
    if form_values:
        values["host"] = form_values.get("host", values["host"])
        values["port"] = form_values.get("port", values["port"])
        values["delay_ms"] = form_values.get("delay_ms", values["delay_ms"])
    logo_url = url_for("static", filename="company_logo.png")
    return render_template_string(
        REPLAY_HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=logo_url,
        favicon_url=url_for("static", filename="favicon.ico"),
        replay_url=url_for("replay"),
        replay_status_url=url_for("replay_status"),
        replay_stop_url=url_for("replay_stop"),
        replay_resume_url=url_for("replay_resume"),
        form_values=values,
        scan_token=scan_token,
        selected_filename=selected_filename,
        summary_lines=summary_lines or [],
        summary_class=summary_class,
        result_lines=result_lines or [],
        result_class=result_class,
        log_lines=log_lines or [],
        replay_token=replay_token,
        replay_total=replay_total,
        replay_status=replay_status,
        back_url=back_url or url_for("index"),
        **nav_context("start", logo_url),
    )


def render_simple_page(title, subtitle, body_html, active_page, page_title=None):
    logo_url = url_for("static", filename="company_logo.png")
    back_url = resolve_back_url(url_for("index"))
    return render_template_string(
        SIMPLE_PAGE_HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=logo_url,
        favicon_url=url_for("static", filename="favicon.ico"),
        title=title,
        subtitle=subtitle,
        body_html=body_html,
        page_title=page_title or title,
        back_url=back_url,
        **nav_context(active_page, logo_url),
    )


def render_generator_page(form_values=None, error_message=""):
    values = form_values if form_values is not None else get_generator_form_values()
    logo_url = url_for("static", filename="company_logo.png")
    return render_template_string(
        GENERATOR_HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=logo_url,
        favicon_url=url_for("static", filename="favicon.ico"),
        generator_url=url_for("generate_log_page"),
        form_values=values,
        error_message=error_message,
        freq_options=EU868_FREQ_OPTIONS,
        datarate_options=EU868_DATARATE_OPTIONS,
        coding_rate_options=EU868_CODING_RATE_OPTIONS,
        payload_examples=PAYLOAD_EXAMPLES,
        **nav_context("files", logo_url),
    )


def render_decode_page(
    scan_token,
    devaddrs,
    credentials,
    summary_lines=None,
    result_class="success",
    missing_keys=None,
    decoders=None,
    selected_decoder="raw",
    decode_results=None,
    selected_filename="",
    export_token="",
    back_url="",
):
    export_csv_url = url_for("export_results", fmt="csv", token=export_token) if export_token else ""
    export_json_url = url_for("export_results", fmt="json", token=export_token) if export_token else ""
    logo_url = url_for("static", filename="company_logo.png")
    return render_template_string(
        DECODE_HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=logo_url,
        favicon_url=url_for("static", filename="favicon.ico"),
        decode_url=url_for("decode"),
        keys_url=url_for("device_keys"),
        scan_token=scan_token,
        summary_lines=summary_lines or [],
        result_class=result_class,
        devaddrs=devaddrs,
        credentials=credentials,
        missing_keys=missing_keys or [],
        decoders=decoders or [],
        selected_decoder=selected_decoder,
        decode_results=decode_results,
        selected_filename=selected_filename,
        export_csv_url=export_csv_url,
        export_json_url=export_json_url,
        back_url=back_url or url_for("index"),
        **nav_context("decoders", logo_url),
    )


def render_device_keys_page(
    credentials,
    summary_lines=None,
    result_class="success",
    scan_token="",
    scan_summary_lines=None,
    scan_filename="",
    back_url="",
):
    known_devaddrs = sorted(credentials.keys())
    decode_url = url_for("decode")
    if scan_token:
        decode_url = f"{decode_url}?scan_token={scan_token}"
    logo_url = url_for("static", filename="company_logo.png")
    return render_template_string(
        DEVICE_KEYS_HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=logo_url,
        favicon_url=url_for("static", filename="favicon.ico"),
        decode_url=decode_url,
        keys_url=url_for("device_keys"),
        summary_lines=summary_lines or [],
        result_class=result_class,
        credentials=credentials,
        known_devaddrs=known_devaddrs,
        scan_token=scan_token,
        scan_summary_lines=scan_summary_lines or [],
        scan_filename=scan_filename,
        back_url=back_url or url_for("index"),
        **nav_context("devices", logo_url),
    )


@app.route("/", methods=["GET"])
def index():
    stored_logs = list_stored_logs()
    return render_main_page(stored_logs=stored_logs)


@app.route("/keys", methods=["GET"])
def keys_redirect():
    return redirect(url_for("device_keys"))


@app.route("/files", methods=["GET"])
def files_page():
    stored_logs = list_stored_logs()
    if stored_logs:
        items = []
        for log in stored_logs:
            log_id = html.escape(log["id"])
            filename = html.escape(log["filename"])
            uploaded_at = html.escape(log["uploaded_at"])
            view_url = url_for("view_log_file", log_id=log["id"])
            download_url = url_for("download_log_file", log_id=log["id"])
            decode_url = url_for("start_decode_from_file", log_id=log["id"])
            replay_url = url_for("start_replay_from_file", log_id=log["id"])
            items.append(
                f"<li class=\"decoder-item\">"
                f"<div>"
                f"<a class=\"decoder-link\" href=\"{view_url}\">{filename}</a>"
                f"<span class=\"decoder-meta\">({uploaded_at})</span>"
                f"</div>"
                f"<div class=\"file-actions\">"
                f"<a class=\"secondary-button\" href=\"{view_url}\">View</a>"
                f"<a class=\"secondary-button\" href=\"{download_url}\">Download</a>"
                f"<a class=\"secondary-button\" href=\"{decode_url}\">Decrypt &amp; decode</a>"
                f"<a class=\"secondary-button\" href=\"{url_for('start_scan_from_file', log_id=log['id'])}\">Scan</a>"
                f"<a class=\"secondary-button\" href=\"{replay_url}\">Replay</a>"
                f"<button type=\"button\" class=\"danger-button danger-text\" "
                f"data-delete-file=\"{log_id}\" "
                f"title=\"Remove log file\" aria-label=\"Remove log file\">🗑<span>Remove</span></button>"
                f"</div>"
                f"</li>"
            )
        stored_html = f"<ul class=\"decoder-list\">{''.join(items)}</ul>"
    else:
        stored_html = "<div class=\"hint\">No stored log files yet.</div>"

    body_html = f"""
      <form method="POST" action="{url_for('delete_log_file')}" data-file-delete-form>
        <input type="hidden" name="log_id" value="" data-file-delete-input>
      </form>
      <div class="field-group">
        <div class="field-header">
          <label>Stored log files</label>
        </div>
        <div class="hint">Review, download, and process previously uploaded logs.</div>
        {stored_html}
      </div>
      <div class="section-divider"></div>
      <div class="logfile-options">
        <div class="logfile-option integration-block">
          <h3>Upload a log file</h3>
          <div class="hint">Upload a new JSONL log and scan it right away.</div>
          <form method="POST" action="{url_for('scan')}" enctype="multipart/form-data" data-scan-url="{url_for('scan')}">
            <input id="logfile" type="file" name="logfile" style="display: none;" aria-hidden="true">
            <input type="hidden" name="redirect_to" value="files">
            <div class="file-drop" data-file-drop>
              <div class="file-text">
                <strong>Click to choose or drag & drop</strong>
                <div class="file-selected" data-file-selected>No file selected</div>
              </div>
            </div>
          </form>
        </div>
        <div class="logfile-option integration-block">
          <h3>Generate a sample log file</h3>
          <div class="hint">Download a ready-made JSONL sample.</div>
          <div class="option-actions">
            <a class="secondary-button" href="{url_for('generate_log_page')}">Generate sample</a>
          </div>
        </div>
      </div>
    """
    return render_simple_page(
        title="Files",
        subtitle="Review stored log files and generate samples.",
        body_html=body_html,
        active_page="files",
    )


@app.route("/decoders", methods=["GET", "POST"])
def decoders_page():
    summary_lines = []
    result_class = "success"
    action = request.form.get("action", "").strip()
    if request.method == "POST" and action == "upload_decoder":
        decoder_file = request.files.get("decoder_file")
        if not decoder_file or not decoder_file.filename:
            summary_lines = ["Please choose a decoder file to upload."]
            result_class = "error"
        else:
            filename = secure_filename(decoder_file.filename)
            if not filename.lower().endswith(".js"):
                summary_lines = ["Decoder file must be a .js file."]
                result_class = "error"
            else:
                ensure_data_dirs()
                path = os.path.join(DECODER_DIR, filename)
                decoder_file.save(path)
                summary_lines = [f"Decoder uploaded: {filename}"]
                result_class = "success"
    if request.method == "POST" and action == "delete_decoder":
        decoder_id = request.form.get("delete_decoder_id", "").strip()
        if not decoder_id:
            summary_lines = ["Select a decoder to remove."]
            result_class = "error"
        elif not decoder_id.startswith("file:"):
            summary_lines = ["Built-in decoders cannot be removed."]
            result_class = "error"
        else:
            try:
                path = resolve_decoder_path(decoder_id)
            except ValueError as exc:
                summary_lines = [str(exc)]
                result_class = "error"
            else:
                if os.path.exists(path):
                    os.remove(path)
                    summary_lines = ["Decoder removed."]
                    result_class = "success"
                else:
                    summary_lines = ["Decoder file not found."]
                    result_class = "error"

    decoders = list_decoders()
    if decoders:
        items = []
        for decoder in decoders:
            label = html.escape(decoder["label"])
            source = html.escape(decoder["source"])
            decoder_id = html.escape(decoder["id"])
            view_url = url_for("view_decoder", decoder_id=decoder["id"])
            actions_html = ""
            if decoder["id"] == "raw":
                actions_html = ""
            else:
                delete_button = ""
                if decoder["id"].startswith("file:"):
                    delete_button = (
                        f"<button type=\"button\" class=\"danger-button danger-text\" "
                        f"data-delete-decoder=\"{decoder_id}\" "
                        f"title=\"Remove decoder\" aria-label=\"Remove decoder\">🗑<span>Remove</span></button>"
                    )
                actions_html = (
                    f"<div class=\"decoder-actions\">"
                    f"<a class=\"secondary-button\" href=\"{view_url}\">View</a>"
                    f"{delete_button}"
                    f"</div>"
                )
            if decoder["id"] == "raw":
                name_html = f"<span class=\"decoder-link\">{label}</span>"
            else:
                name_html = f"<a class=\"decoder-link\" href=\"{view_url}\">{label}</a>"
            items.append(
                f"<li class=\"decoder-item\">"
                f"<div>"
                f"{name_html}"
                f"<span class=\"decoder-meta\">({source})</span>"
                f"</div>"
                f"{actions_html}"
                f"</li>"
            )
        decoder_html = f"<ul class=\"decoder-list\">{''.join(items)}</ul>"
    else:
        decoder_html = "<div class=\"hint\">No decoders available yet.</div>"

    result_html = ""
    if summary_lines:
        summary_items = "".join(f"<div>{html.escape(line)}</div>" for line in summary_lines)
        result_html = f"<div class=\"result {result_class}\">{summary_items}</div>"

    body_html = f"""
      {result_html}
      <form method="POST" action="{url_for('decoders_page')}" data-decoder-delete-form>
        <input type="hidden" name="action" value="delete_decoder">
        <input type="hidden" name="delete_decoder_id" value="" data-decoder-delete-input>
      </form>
      <div class="field-group">
        <div class="field-header">
          <label>Available decoders</label>
        </div>
        <div class="hint">Click a decoder to review its JavaScript.</div>
        {decoder_html}
      </div>
      <div class="section-divider"></div>
      <form method="POST" action="{url_for('decoders_page')}" enctype="multipart/form-data">
        <input type="hidden" name="action" value="upload_decoder">
        <div class="field-group">
          <div class="field-header">
            <label for="decoder_file">Add a decoder</label>
          </div>
          <input id="decoder_file" name="decoder_file" type="file" accept=".js">
          <div class="hint">JS decoders should define <code>Decoder(bytes, port)</code> or <code>decodeUplink({{ bytes, fPort }})</code>.</div>
        </div>
        <div class="form-actions">
          <button type="submit">Upload decoder</button>
        </div>
      </form>
    """
    return render_simple_page(
        title="Decoders",
        subtitle="Upload and select payload decoders for log files.",
        body_html=body_html,
        active_page="decoders",
    )


@app.route("/integrations", methods=["GET"])
def integrations_page():
    body_html = f"""
      <div class="logfile-options">
        <div class="logfile-option integration-block">
          <h3>EarthRanger (HTTP)</h3>
          <div class="hint">Send decoded uplinks to EarthRanger via HTTP integration.</div>
          <div class="option-actions">
            <button type="button" class="secondary-button">Add integration</button>
            <button type="button" class="secondary-button">Manage</button>
          </div>
        </div>
        <div class="logfile-option integration-block">
          <h3>InfluxDB</h3>
          <div class="hint">Stream decoded uplinks into an InfluxDB bucket.</div>
          <div class="option-actions">
            <button type="button" class="secondary-button">Add integration</button>
            <button type="button" class="secondary-button">Manage</button>
          </div>
        </div>
        <div class="logfile-option integration-block">
          <h3>MQTT</h3>
          <div class="hint">Publish decoded uplinks to an MQTT broker.</div>
          <div class="option-actions">
            <button type="button" class="secondary-button">Add integration</button>
            <button type="button" class="secondary-button">Manage</button>
          </div>
        </div>
      </div>
    """
    return render_simple_page(
        title="Integrations",
        subtitle="Connect log playback to external tools and services.",
        body_html=body_html,
        active_page="integrations",
    )


@app.route("/decoders/view", methods=["GET"])
def view_decoder():
    decoder_id = request.args.get("decoder_id", "").strip()
    if not decoder_id:
        return render_simple_page(
            title="Decoder Viewer",
            subtitle="Select a decoder to view its source.",
            body_html="<div class=\"hint\">No decoder selected.</div>",
            active_page="decoders",
            page_title="Decoder Viewer",
        )
    try:
        path = resolve_decoder_path(decoder_id)
    except ValueError as exc:
        return render_simple_page(
            title="Decoder Viewer",
            subtitle="Unable to load decoder.",
            body_html=f"<div class=\"result error\">{html.escape(str(exc))}</div>",
            active_page="decoders",
            page_title="Decoder Viewer",
        )
    if not os.path.exists(path):
        return render_simple_page(
            title="Decoder Viewer",
            subtitle="Decoder not found.",
            body_html="<div class=\"result error\">Decoder file not found.</div>",
            active_page="decoders",
            page_title="Decoder Viewer",
        )
    with open(path, "r", encoding="utf-8") as handle:
        content = handle.read()
    body_html = f"""
      <div class="field-group">
        <div class="field-header">
          <label>{html.escape(os.path.basename(path))}</label>
        </div>
        <pre class="code-block">{html.escape(content)}</pre>
      </div>
      <div class="form-actions">
        <a class="secondary-button" href="{url_for('decoders_page')}">Back to Decoders</a>
      </div>
    """
    return render_simple_page(
        title="Decoder Viewer",
        subtitle="Review the decoder JavaScript before using it.",
        body_html=body_html,
        active_page="decoders",
        page_title="Decoder Viewer",
    )


@app.route("/files/view", methods=["GET"])
def view_log_file():
    log_id = request.args.get("log_id", "").strip()
    entry = get_stored_log_entry(log_id) if log_id else None
    if not entry:
        return render_simple_page(
            title="Log File Viewer",
            subtitle="Log file not found.",
            body_html="<div class=\"result error\">Log file not found.</div>",
            active_page="files",
            page_title="Log File Viewer",
        )
    path = entry["path"]
    max_bytes = 200000
    with open(path, "rb") as handle:
        content_bytes = handle.read(max_bytes + 1)
    truncated = len(content_bytes) > max_bytes
    content_bytes = content_bytes[:max_bytes]
    content = content_bytes.decode("utf-8", errors="replace")
    note = ""
    if truncated:
        note = "<div class=\"hint\">Preview truncated to 200 KB.</div>"
    body_html = f"""
      <div class="field-group">
        <div class="field-header">
          <label>{html.escape(entry["filename"])}</label>
        </div>
        {note}
        <pre class="code-block">{html.escape(content)}</pre>
      </div>
      <div class="form-actions">
        <a class="secondary-button" href="{url_for('files_page')}">Back to Files</a>
      </div>
    """
    return render_simple_page(
        title="Log File Viewer",
        subtitle="Review the stored log file content.",
        body_html=body_html,
        active_page="files",
        page_title="Log File Viewer",
    )


@app.route("/files/download", methods=["GET"])
def download_log_file():
    log_id = request.args.get("log_id", "").strip()
    entry = get_stored_log_entry(log_id) if log_id else None
    if not entry or not os.path.exists(entry["path"]):
        return "Log file not found.", 404
    return send_file(entry["path"], as_attachment=True, download_name=entry["filename"])


@app.route("/files/delete", methods=["POST"])
def delete_log_file():
    log_id = request.form.get("log_id", "").strip()
    if log_id:
        delete_stored_log(log_id)
    return redirect(url_for("files_page"))


@app.route("/files/decode", methods=["GET"])
def start_decode_from_file():
    log_id = request.args.get("log_id", "").strip()
    try:
        scan_token, _entry = scan_stored_log(log_id)
    except ValueError as exc:
        body_html = f"<div class=\"result error\">{html.escape(str(exc))}</div>"
        return render_simple_page(
            title="Files",
            subtitle="Review stored log files and generate samples.",
            body_html=body_html,
            active_page="files",
            page_title="Files",
        )
    return redirect(url_for("decode", scan_token=scan_token))


@app.route("/files/replay", methods=["GET"])
def start_replay_from_file():
    log_id = request.args.get("log_id", "").strip()
    try:
        scan_token, _entry = scan_stored_log(log_id)
    except ValueError as exc:
        body_html = f"<div class=\"result error\">{html.escape(str(exc))}</div>"
        return render_simple_page(
            title="Files",
            subtitle="Review stored log files and generate samples.",
            body_html=body_html,
            active_page="files",
            page_title="Files",
        )
    return redirect(url_for("replay", scan_token=scan_token))


def run_replay_job(token, parsed, host, port, delay_ms, start_index=0, sent=0, errors=0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    total = len(parsed)

    try:
        for idx, rec in enumerate(parsed[start_index:], start=start_index + 1):
            entry = get_replay_job(token)
            if not entry or entry.get("status") != "running":
                break
            gateway_eui = rec["gateway_eui"]
            rxpk = rec["rxpk"]
            send_attempted = False

            try:
                packet = build_push_data(gateway_eui, rxpk)
            except Exception as exc:
                errors += 1
                try:
                    rxpk_serialized = json.dumps(rxpk)
                except Exception:
                    rxpk_serialized = str(rxpk) if rxpk is not None else ""
                rxpk_preview = rxpk_serialized[:100] + "..." if len(rxpk_serialized) > 100 else rxpk_serialized
                try:
                    fcnt = parse_uplink(rxpk)["fcnt"]
                except Exception:
                    fcnt = ""
                append_replay_log(
                    token,
                    {
                        "index": idx,
                        "status": "Error",
                        "send_time_ms": "",
                        "gateway": gateway_eui,
                        "fcnt": fcnt,
                        "freq": rxpk.get("freq"),
                        "size": rxpk.get("size"),
                        "message": f"Build error: {exc} -- {rxpk_preview}",
                        "css": "err",
                    },
                    sent=sent,
                    errors=errors,
                )
                update_replay_job(token, current_index=idx, sent=sent, errors=errors)
                continue

            try:
                sock.sendto(packet, (host, port))
                send_attempted = True
                sent += 1
                send_time_ms = int(time.time() * 1000)
                try:
                    fcnt = parse_uplink(rxpk)["fcnt"]
                except Exception:
                    fcnt = ""
                freq = rxpk.get("freq", "?")
                size = rxpk.get("size", len(packet))
                datr = rxpk.get("datr", "?")
                rssi = rxpk.get("rssi", "?")
                lsnr = rxpk.get("lsnr", "?")
                time_str = rxpk.get("time", "?")
                payload = rxpk.get("data", "")
                payload_preview = (payload[:60] + "...") if payload and len(payload) > 60 else payload or "n/a"
                append_replay_log(
                    token,
                    {
                        "index": idx,
                        "status": "Sent",
                        "send_time_ms": send_time_ms,
                        "gateway": gateway_eui,
                        "fcnt": fcnt,
                        "freq": freq,
                        "size": size,
                        "message": (
                            f"{time_str} datr={datr}, rssi={rssi} dBm, lsnr={lsnr} dB, "
                            f"data={payload_preview}"
                        ),
                        "css": "ok",
                    },
                    sent=sent,
                    errors=errors,
                )
            except Exception as exc:
                send_attempted = True
                errors += 1
                send_time_ms = int(time.time() * 1000)
                try:
                    rxpk_serialized = json.dumps(rxpk)
                except Exception:
                    rxpk_serialized = str(rxpk) if rxpk is not None else ""
                rxpk_preview = rxpk_serialized[:100] + "..." if len(rxpk_serialized) > 100 else rxpk_serialized
                try:
                    fcnt = parse_uplink(rxpk)["fcnt"]
                except Exception:
                    fcnt = ""
                append_replay_log(
                    token,
                    {
                        "index": idx,
                        "status": "Error",
                        "send_time_ms": send_time_ms,
                        "gateway": gateway_eui,
                        "fcnt": fcnt,
                        "freq": rxpk.get("freq"),
                        "size": rxpk.get("size"),
                        "message": f"Send error: {exc} -- {rxpk_preview}",
                        "css": "err",
                    },
                    sent=sent,
                    errors=errors,
                )

            if send_attempted and delay_ms > 0 and idx < total:
                time.sleep(delay_ms / 1000.0)
            update_replay_job(token, current_index=idx, sent=sent, errors=errors)
    finally:
        sock.close()
        entry = get_replay_job(token)
        status = entry.get("status") if entry else "done"
        if status == "running":
            status = "done"
        update_replay_job(token, status=status, sent=sent, errors=errors)


@app.route("/files/scan", methods=["GET"])
def start_scan_from_file():
    log_id = request.args.get("log_id", "").strip()
    try:
        scan_token, _entry = scan_stored_log(log_id)
    except ValueError as exc:
        body_html = f"<div class=\"result error\">{html.escape(str(exc))}</div>"
        return render_simple_page(
            title="Files",
            subtitle="Review stored log files and generate samples.",
            body_html=body_html,
            active_page="files",
            page_title="Files",
        )
    return redirect(url_for("device_keys", scan_token=scan_token, show_scan="1"))


@app.route("/about", methods=["GET"])
def about_page():
    logo_url = url_for("static", filename="company_logo.png")
    body_html = f"""
      <div class="logfile-options">
        <div class="logfile-option">
          <h3>About Smart Parks</h3>
          <div style="display: flex; align-items: center; gap: 0.8rem; margin: 0.6rem 0;">
            <img src="{logo_url}" alt="Smart Parks logo" style="width: 52px; height: auto;">
            <div class="hint">Protect Wildlife with Passion and Technology.</div>
          </div>
          <div class="hint">Smart Parks is a conservation technology organization focused on protecting wildlife and empowering rangers with resilient field tools.</div>
          <div class="hint">Their solutions combine on-animal sensors, ranger communications, and real-time monitoring to support anti-poaching and animal welfare across protected areas.</div>
          <div class="option-actions">
            <a class="secondary-button" href="https://www.smartparks.org" target="_blank" rel="noopener">www.smartparks.org</a>
          </div>
        </div>
        <div class="logfile-option">
          <h3>About the App</h3>
          <div class="hint">OpenCollar LP0 Replay tool helps replay, decrypt, and decode LoRaWAN uplinks captured as Semtech UDP JSONL logs.</div>
          <div class="hint">Use it to validate uplink pipelines, tune forwarders, and inspect payloads during field tests.</div>
        </div>
      </div>
    """
    return render_simple_page(
        title="About",
        subtitle="Product info and organization details.",
        body_html=body_html,
        active_page="about",
    )


@app.route("/scan", methods=["POST"])
def scan():
    logfile = request.files.get("logfile")
    stored_log_id = request.form.get("stored_log_id", "").strip()
    redirect_to = request.form.get("redirect_to", "").strip()
    stored_logs = list_stored_logs()
    selected_filename = ""
    selected_stored_id = stored_log_id

    stream = None
    if logfile and logfile.filename:
        entry = store_uploaded_log(logfile)
        selected_filename = entry["filename"]
        selected_stored_id = entry["id"]
        stored_logs = list_stored_logs()
        if redirect_to == "files":
            return redirect(url_for("files_page"))
        stream = open(entry["path"], "rb")
    elif stored_log_id:
        entry = get_stored_log_entry(stored_log_id)
        if entry:
            selected_filename = entry["filename"]
            stream = open(entry["path"], "rb")

    if stream is None:
        if redirect_to == "files":
            return redirect(url_for("files_page"))
        return render_main_page(
            ["Please upload a logfile or select a stored logfile."],
            "error",
            form_values=request.form,
            stored_logs=stored_logs,
            selected_stored_id=selected_stored_id,
        )

    with stream:
        parsed, gateways, devaddrs, scan_errors = scan_logfile(stream)
    summary_lines = [
        "Logfile scan summary:",
        f"Uplinks (valid)={len(parsed)}",
        format_list("Gateway EUI", gateways),
        format_list("DevAddr (hex)", devaddrs),
    ]

    if scan_errors:
        error_lines = summary_lines + [
            f"Validation errors={len(scan_errors)}."
        ]
        preview = scan_errors[:10]
        error_lines.extend(preview)
        if len(scan_errors) > len(preview):
            error_lines.append(f"... (+{len(scan_errors) - len(preview)} more)")
        return render_main_page(
            error_lines,
            "error",
            form_values=request.form,
            selected_filename=selected_filename,
            stored_logs=stored_logs,
            selected_stored_id=selected_stored_id,
        )

    if not parsed:
        return render_main_page(
            summary_lines + ["No valid uplinks found."],
            "error",
            form_values=request.form,
            selected_filename=selected_filename,
            stored_logs=stored_logs,
            selected_stored_id=selected_stored_id,
        )

    scan_token = store_scan_result(parsed, gateways, devaddrs, selected_filename, selected_stored_id)
    return render_main_page(
        summary_lines + ["Scan complete. Ready to replay or decrypt."],
        "success",
        form_values=request.form,
        scan_token=scan_token,
        selected_filename=selected_filename,
        stored_logs=stored_logs,
        selected_stored_id=selected_stored_id,
    )


@app.route("/replay/status", methods=["GET"])
def replay_status():
    token = request.args.get("token", "").strip()
    if not token:
        return jsonify({"error": "missing_token"}), 400
    entry = get_replay_job(token)
    if not entry:
        return jsonify({"error": "not_found"}), 404
    since_raw = request.args.get("since", "0").strip()
    try:
        since = int(since_raw)
    except ValueError:
        since = 0
    with REPLAY_LOCK:
        lines = entry["log_lines"][since:]
        payload = {
            "status": entry["status"],
            "total": entry["total"],
            "sent": entry["sent"],
            "errors": entry["errors"],
            "host": entry["host"],
            "port": entry["port"],
            "delay_ms": entry["delay_ms"],
            "lines": lines,
            "count": len(entry["log_lines"]),
        }
    return jsonify(payload)


@app.route("/replay/stop", methods=["POST"])
def replay_stop():
    token = request.form.get("replay_token", "").strip()
    scan_token = request.form.get("scan_token", "").strip()
    if token:
        entry = get_replay_job(token)
        if entry and entry.get("status") == "running":
            send_time_ms = int(time.time() * 1000)
            append_replay_log(
                token,
                {
                    "index": "",
                    "status": "Stopped",
                    "send_time_ms": send_time_ms,
                    "gateway": "",
                    "fcnt": "",
                    "freq": "",
                    "size": "",
                    "message": "Replay stopped by user.",
                    "css": "err",
                },
            )
            update_replay_job(token, status="stopped")
    return redirect(url_for("replay", scan_token=scan_token, replay_token=token))


@app.route("/replay/resume", methods=["POST"])
def replay_resume():
    token = request.form.get("replay_token", "").strip()
    scan_token = request.form.get("scan_token", "").strip()
    entry = get_replay_job(token) if token else None
    if not entry or entry.get("status") != "stopped":
        return redirect(url_for("replay", scan_token=scan_token))
    cached = get_scan_result(scan_token)
    if not cached:
        return redirect(url_for("replay", scan_token=scan_token))

    parsed, _gateways, _devaddrs, _selected_filename, _stored_log_id = cached
    start_index = min(int(entry.get("current_index", 0)), len(parsed))
    host = entry.get("host", "127.0.0.1")
    port = int(entry.get("port", 1700))
    delay_ms = int(entry.get("delay_ms", 500))
    sent = int(entry.get("sent", 0))
    errors = int(entry.get("errors", 0))
    log_lines = list(entry.get("log_lines", []))

    job_token = store_replay_job(
        len(parsed),
        host,
        port,
        delay_ms,
        start_index=start_index,
        sent=sent,
        errors=errors,
        log_lines=log_lines,
    )
    thread = threading.Thread(
        target=run_replay_job,
        args=(job_token, parsed, host, port, delay_ms, start_index, sent, errors),
        daemon=True,
    )
    thread.start()
    return redirect(url_for("replay", scan_token=scan_token, replay_token=job_token))


@app.route("/replay", methods=["GET", "POST"])
def replay():
    scan_token = (request.values.get("scan_token") or "").strip()
    back_url = resolve_back_url(url_for("index"))
    if not scan_token:
        return render_replay_page(
            summary_lines=["Scan a logfile first."],
            summary_class="error",
            back_url=back_url,
        )

    cached = get_scan_result(scan_token)
    if not cached:
        return render_replay_page(
            summary_lines=["Scan expired or not found. Please upload the logfile again."],
            summary_class="error",
            scan_token=scan_token,
            back_url=back_url,
        )

    parsed, gateways, devaddrs, selected_filename, _stored_log_id = cached
    summary_lines = [
        "Logfile scan summary:",
        f"Uplinks (valid)={len(parsed)}",
        format_list("Gateway EUI", gateways),
        format_list("DevAddr (hex)", devaddrs),
    ]

    replay_token = request.args.get("replay_token", "").strip()
    replay_job = get_replay_job(replay_token) if replay_token else None

    if request.method == "GET":
        form_values = None
        replay_total = 0
        replay_status = ""
        result_lines = None
        result_class = ""
        if replay_token and replay_job:
            form_values = {
                "host": replay_job.get("host", "127.0.0.1"),
                "port": str(replay_job.get("port", "1700")),
                "delay_ms": str(replay_job.get("delay_ms", "500")),
            }
            replay_total = replay_job.get("total", 0)
            replay_status = replay_job.get("status", "")
        elif replay_token and not replay_job:
            result_lines = ["Replay job not found or expired."]
            result_class = "error"
        return render_replay_page(
            form_values=form_values,
            scan_token=scan_token,
            selected_filename=selected_filename,
            summary_lines=summary_lines,
            summary_class="success",
            result_lines=result_lines,
            result_class=result_class,
            replay_token=replay_token if replay_job else "",
            replay_total=replay_total,
            replay_status=replay_status,
            back_url=back_url,
        )

    host = request.form.get("host", "").strip() or "127.0.0.1"
    port_raw = request.form.get("port", "1700").strip()
    delay_raw = request.form.get("delay_ms", "500").strip()

    try:
        port = int(port_raw)
    except ValueError:
        return render_replay_page(
            form_values=request.form,
            scan_token=scan_token,
            selected_filename=selected_filename,
            summary_lines=summary_lines,
            summary_class="success",
            result_lines=[f"Invalid UDP port: {port_raw}"],
            result_class="error",
            back_url=back_url,
        )

    try:
        delay_ms = int(delay_raw)
        if delay_ms < 0:
            raise ValueError("delay must be non-negative")
    except ValueError:
        return render_replay_page(
            form_values=request.form,
            scan_token=scan_token,
            selected_filename=selected_filename,
            summary_lines=summary_lines,
            summary_class="success",
            result_lines=[f"Invalid delay in milliseconds: {delay_raw}"],
            result_class="error",
            back_url=back_url,
        )

    if not parsed:
        return render_replay_page(
            form_values=request.form,
            scan_token=scan_token,
            selected_filename=selected_filename,
            summary_lines=summary_lines,
            summary_class="error",
            result_lines=["No valid uplinks found."],
            result_class="error",
            back_url=back_url,
        )

    job_token = store_replay_job(len(parsed), host, port, delay_ms)
    thread = threading.Thread(
        target=run_replay_job,
        args=(job_token, parsed, host, port, delay_ms, 0, 0, 0),
        daemon=True,
    )
    thread.start()
    return redirect(url_for("replay", scan_token=scan_token, replay_token=job_token))


def get_missing_keys(devaddrs, credentials):
    missing = []
    for devaddr in devaddrs:
        entry = credentials.get(devaddr, {})
        nwk = entry.get("nwk_skey", "")
        app = entry.get("app_skey", "")
        if not nwk or not app or len(nwk) != 32 or len(app) != 32:
            missing.append(devaddr)
    return missing


@app.route("/decode", methods=["GET", "POST"])
def decode():
    scan_token = request.form.get("scan_token") or request.args.get("scan_token", "")
    scan_token = scan_token.strip()
    back_url = resolve_back_url(url_for("index"))
    if not scan_token:
        return render_main_page(["Scan a logfile first."], "error", stored_logs=list_stored_logs())

    cached = get_scan_result(scan_token)
    if not cached:
        return render_main_page(
            ["Scan expired or not found. Please upload the logfile again."],
            "error",
            stored_logs=list_stored_logs(),
        )

    parsed, gateways, devaddrs, selected_filename, stored_log_id = cached
    credentials = load_credentials()
    missing_keys = get_missing_keys(devaddrs, credentials)
    summary_lines = [
        "Logfile scan summary:",
        f"Uplinks (valid)={len(parsed)}",
        format_list("Gateway EUI", gateways),
        format_list("DevAddr (hex)", devaddrs),
    ]
    decoders = list_decoders()
    selected_decoder = request.form.get("decoder_id", "raw")
    decode_results = None
    export_token = ""
    result_class = "success"

    action = request.form.get("action", "").strip()
    if action == "add_device":
        devaddr_raw = request.form.get("new_devaddr", "").strip()
        name_val = request.form.get("new_name", "").strip()
        nwk_val = request.form.get("new_nwk", "").strip()
        app_val = request.form.get("new_app", "").strip()
        if not devaddr_raw:
            summary_lines = ["DevAddr is required to add a device."]
            result_class = "error"
        else:
            try:
                devaddr = normalize_devaddr(devaddr_raw)
            except ValueError as exc:
                summary_lines = [str(exc)]
                result_class = "error"
            else:
                if (nwk_val or app_val) and not (nwk_val and app_val):
                    summary_lines = ["Provide both NwkSKey and AppSKey, or leave both empty."]
                    result_class = "error"
                else:
                    entry = credentials.get(devaddr, {})
                    if name_val:
                        entry["name"] = name_val
                    if nwk_val and app_val:
                        try:
                            entry["nwk_skey"] = normalize_skey(nwk_val, f"NwkSKey for {devaddr}")
                            entry["app_skey"] = normalize_skey(app_val, f"AppSKey for {devaddr}")
                        except ValueError as exc:
                            summary_lines = [str(exc)]
                            result_class = "error"
                            return render_decode_page(
                                scan_token=scan_token,
                                devaddrs=devaddrs,
                                credentials=credentials,
                                summary_lines=summary_lines,
                                result_class=result_class,
                                missing_keys=missing_keys,
                                decoders=decoders,
                                selected_decoder=selected_decoder,
                                decode_results=decode_results,
                                selected_filename=selected_filename,
                                export_token=export_token,
                                back_url=back_url,
                            )
                    entry["updated_at"] = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                    credentials[devaddr] = entry
                    save_credentials(credentials)
                    summary_lines = [f"Device {devaddr} saved."]
                    result_class = "success"

        missing_keys = get_missing_keys(devaddrs, credentials)
        return render_decode_page(
            scan_token=scan_token,
            devaddrs=devaddrs,
            credentials=credentials,
            summary_lines=summary_lines,
            result_class=result_class,
            missing_keys=missing_keys,
            decoders=decoders,
            selected_decoder=selected_decoder,
            decode_results=decode_results,
            selected_filename=selected_filename,
            export_token=export_token,
            back_url=back_url,
        )

    if action == "upload_decoder":
        decoder_file = request.files.get("decoder_file")
        if not decoder_file or not decoder_file.filename:
            summary_lines = ["Please choose a decoder file to upload."]
            result_class = "error"
        else:
            filename = secure_filename(decoder_file.filename)
            if not filename.lower().endswith(".js"):
                summary_lines = ["Decoder file must be a .js file."]
                result_class = "error"
            else:
                ensure_data_dirs()
                path = os.path.join(DECODER_DIR, filename)
                decoder_file.save(path)
                summary_lines = [f"Decoder uploaded: {filename}"]
                result_class = "success"
                decoders = list_decoders()

    if action == "decode":
        if missing_keys:
            summary_lines = ["Missing keys. Save keys before decoding."]
            result_class = "error"
        else:
            try:
                decoder_func = load_decoder(selected_decoder)
            except Exception as exc:
                summary_lines = [f"Decoder error: {exc}"]
                result_class = "error"
            else:
                rows = []
                ok = 0
                errors = 0
                for idx, rec in enumerate(parsed, start=1):
                    rxpk = rec["rxpk"]
                    gateway_eui = rec["gateway_eui"]
                    time_str = rxpk.get("time", "")
                    freq = rxpk.get("freq", "")
                    status = "Decoded"
                    css = "ok"
                    payload_hex = ""
                    decoded_preview = ""
                    decoded_data = None
                    decoded_raw = None
                    devaddr = ""
                    fcnt = ""
                    fport = ""
                    error_msg = ""

                    try:
                        uplink = parse_uplink(rxpk)
                        devaddr = uplink["devaddr"]
                        fcnt = uplink["fcnt"]
                        fport = uplink["fport"] if uplink["fport"] is not None else ""
                        keys = credentials.get(devaddr, {})
                        nwk_skey = hex_to_bytes(keys["nwk_skey"], "NwkSKey")
                        app_skey = hex_to_bytes(keys["app_skey"], "AppSKey")
                        key = app_skey if uplink["fport"] not in (0, None) else nwk_skey
                        decrypted = lorawan_decrypt_payload(
                            key, uplink["devaddr_le"], uplink["fcnt"], uplink["frm_payload"], direction=0
                        )
                        payload_hex = decrypted.hex().upper()
                        decoded_raw = decoder_func(decrypted, uplink["fport"], devaddr, rxpk)
                        if isinstance(decoded_raw, dict) and "data" in decoded_raw and len(decoded_raw) <= 3:
                            decoded_data = decoded_raw.get("data")
                        else:
                            decoded_data = decoded_raw
                        decoded_preview = json.dumps(decoded_data, ensure_ascii=True)
                        ok += 1
                    except Exception as exc:
                        status = "Error"
                        css = "err"
                        error_msg = str(exc)
                        decoded_preview = error_msg
                        errors += 1

                    rows.append(
                        {
                            "index": idx,
                            "status": status,
                            "devaddr": devaddr,
                            "fcnt": fcnt,
                            "fport": fport,
                            "time": time_str,
                            "gateway_eui": gateway_eui,
                            "freq": freq,
                            "payload_hex": payload_hex,
                            "decoded": decoded_data,
                            "decoded_raw": decoded_raw,
                            "error": error_msg,
                            "decoded_preview": decoded_preview,
                            "css": css,
                        }
                    )

                decode_results = rows
                export_token = store_decode_result(rows)
                summary_lines = [
                    "Decode complete.",
                    f"Decoded={ok}, errors={errors}",
                ]
                result_class = "success" if errors == 0 else "error"

    return render_decode_page(
        scan_token=scan_token,
        devaddrs=devaddrs,
        credentials=credentials,
        summary_lines=summary_lines,
        result_class=result_class,
        missing_keys=missing_keys,
        decoders=decoders,
        selected_decoder=selected_decoder,
        decode_results=decode_results,
        selected_filename=selected_filename,
        export_token=export_token,
        back_url=back_url,
    )


@app.route("/devices", methods=["GET", "POST"])
def device_keys():
    scan_token = request.form.get("scan_token") or request.args.get("scan_token", "")
    scan_token = scan_token.strip()
    back_url = resolve_back_url(url_for("index"))
    credentials = load_credentials()
    summary_lines = []
    result_class = "success"
    scan_summary_lines = []
    scan_filename = ""

    if request.args.get("show_scan") and scan_token:
        cached = get_scan_result(scan_token)
        if cached:
            parsed, gateways, devaddrs, scan_filename, _stored_log_id = cached
            scan_summary_lines = [
                "Logfile scan summary:",
                f"Uplinks (valid)={len(parsed)}",
                format_list("Gateway EUI", gateways),
                format_list("DevAddr (hex)", devaddrs),
            ]

    action = request.form.get("action", "").strip()
    if action == "delete_device":
        devaddr = request.form.get("delete_devaddr", "").strip()
        if not devaddr:
            summary_lines = ["Select a device to remove."]
            result_class = "error"
        elif devaddr not in credentials:
            summary_lines = [f"Device {devaddr} not found."]
            result_class = "error"
        else:
            credentials.pop(devaddr, None)
            save_credentials(credentials)
            summary_lines = [f"Device {devaddr} removed."]
            result_class = "success"
        return render_device_keys_page(
            credentials,
            summary_lines=summary_lines,
            result_class=result_class,
            scan_token=scan_token,
            scan_summary_lines=scan_summary_lines,
            scan_filename=scan_filename,
            back_url=back_url,
        )

    if action == "save_keys":
        updated = 0
        errors = []
        for devaddr in list(credentials.keys()):
            name_val = request.form.get(f"name_{devaddr}", "").strip()
            nwk_val = request.form.get(f"nwk_{devaddr}", "").strip()
            app_val = request.form.get(f"app_{devaddr}", "").strip()
            entry = credentials.get(devaddr, {})
            if name_val:
                entry["name"] = name_val
            if nwk_val or app_val:
                if not nwk_val or not app_val:
                    errors.append(f"Both keys required for {devaddr}.")
                else:
                    try:
                        entry["nwk_skey"] = normalize_skey(nwk_val, f"NwkSKey for {devaddr}")
                        entry["app_skey"] = normalize_skey(app_val, f"AppSKey for {devaddr}")
                    except ValueError as exc:
                        errors.append(str(exc))
            entry["updated_at"] = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            credentials[devaddr] = entry
            updated += 1
        if errors:
            summary_lines = ["Key update errors:"] + errors
            result_class = "error"
        else:
            summary_lines = [f"Updated {updated} device(s)."]
        save_credentials(credentials)

    if action == "add_device":
        devaddr_raw = request.form.get("new_devaddr", "").strip()
        name_val = request.form.get("new_name", "").strip()
        nwk_val = request.form.get("new_nwk", "").strip()
        app_val = request.form.get("new_app", "").strip()
        if not devaddr_raw:
            summary_lines = ["DevAddr is required to add a device."]
            result_class = "error"
        else:
            try:
                devaddr = normalize_devaddr(devaddr_raw)
            except ValueError as exc:
                summary_lines = [str(exc)]
                result_class = "error"
            else:
                if (nwk_val or app_val) and not (nwk_val and app_val):
                    summary_lines = ["Provide both NwkSKey and AppSKey, or leave both empty."]
                    result_class = "error"
                else:
                    entry = credentials.get(devaddr, {})
                    if name_val:
                        entry["name"] = name_val
                    if nwk_val and app_val:
                        try:
                            entry["nwk_skey"] = normalize_skey(nwk_val, f"NwkSKey for {devaddr}")
                            entry["app_skey"] = normalize_skey(app_val, f"AppSKey for {devaddr}")
                        except ValueError as exc:
                            summary_lines = [str(exc)]
                            result_class = "error"
                            return render_device_keys_page(
                                credentials,
                                summary_lines=summary_lines,
                                result_class=result_class,
                                scan_token=scan_token,
                                back_url=back_url,
                            )
                    entry["updated_at"] = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                    credentials[devaddr] = entry
                    save_credentials(credentials)
                    summary_lines = [f"Device {devaddr} saved."]
                    result_class = "success"

    return render_device_keys_page(
        credentials,
        summary_lines=summary_lines,
        result_class=result_class,
        scan_token=scan_token,
        scan_summary_lines=scan_summary_lines,
        scan_filename=scan_filename,
        back_url=back_url,
    )


@app.route("/export/<fmt>", methods=["GET"])
def export_results(fmt):
    token = request.args.get("token", "").strip()
    rows = get_decode_result(token)
    if not rows:
        return "No export data available.", 404

    export_rows = []
    for row in rows:
        export_rows.append(
            {
                "index": row.get("index"),
                "status": row.get("status"),
                "devaddr": row.get("devaddr"),
                "fcnt": row.get("fcnt"),
                "fport": row.get("fport"),
                "time": row.get("time"),
                "gateway_eui": row.get("gateway_eui"),
                "freq": row.get("freq"),
                "payload_hex": row.get("payload_hex"),
                "decoded": json.dumps(row.get("decoded"), ensure_ascii=True) if row.get("decoded") is not None else "",
                "decoded_raw": json.dumps(row.get("decoded_raw"), ensure_ascii=True) if row.get("decoded_raw") is not None else "",
                "error": row.get("error"),
            }
        )

    if fmt == "json":
        buffer = io.BytesIO(json.dumps(export_rows, indent=2).encode("utf-8"))
        buffer.seek(0)
        return send_file(buffer, mimetype="application/json", as_attachment=True, download_name="decoded_payloads.json")

    if fmt == "csv":
        buffer = io.StringIO()
        fieldnames = list(export_rows[0].keys())
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(export_rows)
        csv_bytes = io.BytesIO(buffer.getvalue().encode("utf-8"))
        csv_bytes.seek(0)
        return send_file(csv_bytes, mimetype="text/csv", as_attachment=True, download_name="decoded_payloads.csv")

    return "Unsupported export format.", 400


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
