from app import app,logging
from config import Config
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import ssl

def send_email(subject=str, to=str, cc='', body='', is_html=True):

    SMTP_HOST =             app.config['SMTP_HOST']
    SMTP_USERNAME =         app.config['SMTP_USERNAME']
    SMTP_PASSWORD =         app.config['SMTP_PASSWORD']
    SMTP_PORT =             app.config['SMTP_PORT']
    SMTP_TLS =              app.config['SMTP_TLS']
    SMTP_FROM_ADDRESS =     app.config['SMTP_FROM_ADDRESS']
    SMTP_LOGIN_REQUIRED =   app.config['SMTP_LOGIN_REQUIRED']
    SMTP_IGNORE_CERT =      app.config['SMTP_IGNORE_CERT']

    logger = logging.getLogger('accounts-helpers')

    logger.info("Connection details: Host: %s Port: %s TLS: %s Ignore Cert: %s Login Required: %s as %s" % (SMTP_HOST, SMTP_PORT, SMTP_TLS, SMTP_IGNORE_CERT, SMTP_LOGIN_REQUIRED, SMTP_USERNAME))
    logger.info("from: %s subject: %s to: %s  body: %s" % (SMTP_FROM_ADDRESS, subject, to, body))

    

    # TODO, currently doesn't work because of ssl.SSLError: [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1045)
    # In addition, the certificate isn't properly ignored.
    #if SMTP_SSL:
    #    if SMTP_IGNORE_CERT:
    #        context = ssl._create_unverified_context(protocol=ssl.PROTOCOL_TLSv1_1)
    #        context.check_hostname = False
    #        context.verify_mode = ssl.CERT_NONE
    #        s = smtplib.SMTP_SSL(host=SMTP_HOST, port=SMTP_PORT, context=context)
    #    else:
    #        s = smtplib.SMTP_SSL(host=SMTP_HOST, port=SMTP_PORT)
    #else:
    #    s = smtplib.SMTP(host=SMTP_HOST, port=SMTP_PORT)

    s = smtplib.SMTP(host=SMTP_HOST, port=SMTP_PORT)

    try:
        s.ehlo()
    except Exception as e:
        logger.error("SMTP EHLO Error caught: %s" % e)
        return False

    if SMTP_TLS:
        
        # TODO, Not sure what's going on here. Even if we give a bogus servername, starttls still connects without warning.
        # Basically, SMTP_IGNORE_CERT fails insecurely and will always send the message.
        if SMTP_IGNORE_CERT:
            context = ssl._create_unverified_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        

        try:
            s.starttls()
        except Exception as e:
            logger.error("SMTP STARTTLS Error caught: %s" % e)
            return False

    if SMTP_LOGIN_REQUIRED:
        try:
            s.login(SMTP_USERNAME, SMTP_PASSWORD)
        except Exception as e:
            logger.error("SMTP Login Error caught: %s" % e)
            return False
    
    envelope = MIMEMultipart()

    envelope['From'] = SMTP_FROM_ADDRESS
    envelope['To'] = to
    envelope['Subject'] = subject

    if is_html:
        envelope.attach(MIMEText(body,'html'))
    else:
        envelope.attach(MIMEText(body,'plain'))

    try:
        s.send_message(envelope)
        return True
    except Exception as e:
        logger.error("SMTP Error caught: %s" % e)
        return False