from django.core.mail import EmailMessage
import threading

class EmailThread(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)


    def run(self):
        self.email.send(fail_silently=False)

class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(subject=data['subject'], body=data['body'], to=[data['to_email']])
        EmailThread(email).start()
        # email.send(fail_silently=False)

    @staticmethod
    def after_verification (data):
        email = EmailMessage(subject=data['subject'], body=data['body'], to=[data['to_email']])
        EmailThread(email).start()
