import smtplib

msg = """Subject: Python test

Hello from Python!
"""

with smtplib.SMTP('127.0.0.1', 1025) as s:
    s.set_debuglevel(1)
    s.sendmail('you@example.com', ['check@mailtest.justfortesting.xyz'], msg)
