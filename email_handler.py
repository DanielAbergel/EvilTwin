import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def send_email(email_receiver, network):
    sender_email = ""  # need to fill
    receiver_email = email_receiver
    password = ''  # need to fill
    message = MIMEMultipart("alternative")
    message["Subject"] = "Network Attack Warning"
    message["From"] = sender_email
    message["To"] = receiver_email

    # Create the plain-text and HTML version of your message
    text = """
    There is an attack on the network with Name  = {} , the defending is active and the WIFI will be not 
    available until we can figure it out.
    thanks for the understanding.
    ATTACK TOOL.
    """.format(network)

    # Turn these into plain/html MIMEText objects
    part1 = MIMEText(text, "plain")

    # Add HTML/plain-text parts to MIMEMultipart message
    # The email client will try to render the last part first
    message.attach(part1)

    # Create secure connection with server and send email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(
            sender_email, receiver_email, message.as_string()
        )

