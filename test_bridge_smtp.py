import smtplib
import socket

HOST = "127.0.0.1"  # Force IPv4 (not localhost)
PORT = 10025

print(f"Connecting to {HOST}:{PORT}")

FROM = "you@example.com"
TO = "check@mailtest.justfortesting.xyz"

msg = """Subject: Bridge test

Hello from smtplib through the bridge.
"""

print("DNS lookup:", socket.getaddrinfo("localhost", 10025))
print("Connecting to:", HOST, PORT, "type:", type(PORT))

with smtplib.SMTP(HOST, PORT, timeout=10) as s:
    s.set_debuglevel(1)
    s.sendmail(FROM, [TO], msg)
    print("✅ SMTP test complete")
