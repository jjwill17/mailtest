# smtp/app.py
import asyncio
import os
import base64
import re

import requests
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Sink


API_BASE_URL = os.getenv("API_BASE_URL", "http://api:8080")
_RETURN_PATH_HEADER_RE = re.compile(r"(?im)^return-path:")


class MailHandler(Sink):
    async def handle_DATA(self, server, session, envelope):
        # Use envelope.original_content for raw bytes
        raw_bytes = getattr(envelope, 'original_content', b'')
        if not isinstance(raw_bytes, (bytes, bytearray)):
            raw_bytes = str(raw_bytes).encode("utf-8", errors="replace")
        raw_bytes = bytes(raw_bytes)
        raw_str = raw_bytes.decode("utf-8", errors="replace")
        envelope_from = (envelope.mail_from or "").strip()
        display_from = envelope_from if envelope_from else "<>"
        capture_lines = [f"X-Mailtest-Envelope-From: {display_from}"]
        if not _RETURN_PATH_HEADER_RE.search(raw_str):
            capture_lines.append(f"Return-Path: <{display_from}>")
        peer = getattr(session, "peer", None)
        if peer and isinstance(peer, (list, tuple)) and peer[0]:
            capture_lines.append(f"X-Mailtest-Client-IP: {peer[0]}")
        raw_str = "\n".join(capture_lines) + "\n" + raw_str
        raw_b64 = base64.b64encode(raw_str.encode("utf-8", errors="replace")).decode("ascii")

        subject = envelope.mail_from or "No subject"

        print(f"Received message from {envelope.mail_from}")
        print(f"To: {envelope.rcpt_tos}")
        print(f"Subject preview: {subject[:50]}...")

        try:
            resp = requests.post(
                f"{API_BASE_URL}/ingest",
                json={
                    "subject": subject,
                    "raw_message": raw_str,
                    "raw_message_b64": raw_b64,
                },
                timeout=5,
            )
            print(f"Ingest response: {resp.status_code} {resp.text}")
        except Exception as e:
            print(f"Error posting to API: {e}")

        return "250 Message accepted for delivery"


def main():
    handler = MailHandler()
    controller = Controller(handler, hostname="0.0.0.0", port=2525)
    controller.start()
    print("SMTP server listening on 0.0.0.0:2525")
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_forever()
    except KeyboardInterrupt:
        controller.stop()


if __name__ == "__main__":
    main()
