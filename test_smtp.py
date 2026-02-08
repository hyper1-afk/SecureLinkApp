import smtplib

# Try different GoDaddy SMTP options
servers = [
    ('smtpout.secureserver.net', 587, True),   # TLS
    ('smtpout.secureserver.net', 465, False),  # SSL
    ('smtp.secureserver.net', 587, True),      # Alternative
    ('smtp.secureserver.net', 465, False),     # Alternative SSL
]

password = 'SecureLink2001!'

for host, port, use_tls in servers:
    try:
        print(f"Trying {host}:{port} (TLS={use_tls})...")
        if use_tls:
            s = smtplib.SMTP(host, port, timeout=10)
            s.starttls()
        else:
            s = smtplib.SMTP_SSL(host, port, timeout=10)
        s.login('support@securelinkapp.com', password)
        print(f"SUCCESS with {host}:{port}!")
        s.quit()
        break
    except Exception as e:
        print(f"  Failed: {e}")
