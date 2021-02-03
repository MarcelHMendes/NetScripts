import sys
import smtplib, ssl
from getpass import getpass

if sys.version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")

port = 465
smtp_server = "smtp.mail.yahoo.com"
sender_email = "test@yahoo.com"
receiver_email = "test@yahoo.com"
pswd = getpass('Token:')

text = "Hello!"

message="\r\n".join([
  "From: test@yahoo.com",
  "To: test@yahoo.com",
  "Subject: Just a message<>",
  "",
  text
  ])

context = ssl.create_default_context()
with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
    server.login(sender_email, pswd)
    server.sendmail(sender_email, receiver_email, message)
