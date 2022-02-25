from django.core.mail import EmailMessage


class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(subject=data['subject'], body=data['body'], to=[data['to_email']])
        email.send(fail_silently=False)

    @staticmethod
    def after_verification(data):
        email = EmailMessage(subject=data['subject'], body=data['body'], to=[data['to_email']])
        email.send(fail_silently=False)
