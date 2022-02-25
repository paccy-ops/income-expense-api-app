import jwt
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.utils.encoding import smart_str, force_str, smart_bytes, \
    DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import generics, views
from rest_framework import permissions
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from authentication import serializers
from authentication.models import User
from authentication.renderers import UserRender
from authentication.utils import Util


# Create your views here.

class RegisterView(generics.GenericAPIView):
    """register new user"""
    serializer_class = serializers.RegisterSerializer
    renderer_classes = (UserRender,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token
        relativelink = reverse('authentication:email-verify')
        domain = get_current_site(request).domain
        absurl = f'http://{domain}{relativelink}?token={str(token)}'
        subject = "Verify Your email"
        email_body = f"Hi your registered as {user.username} in expense, " \
                     f"use link below to verify your email " \
                     f"\n{absurl}"
        email_data_to_send = {'subject': subject, 'body': email_body, 'to_email': user.email}
        Util.send_email(email_data_to_send)
        res = {
            "user": user_data,
            "message": "Please check your email box to verify your email"
        }
        return Response(res, status=status.HTTP_201_CREATED)

    # email_param_config = openapi.Parameter(
    #     'email', in_=openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Email"
    # )
    #
    # @swagger_auto_schema(manual_parameters=[email_param_config])
    # def get(self, request):
    #     email = request.GET.get('email')
    #     if User.objects.filter(email=email).exists():
    #         user = User.objects.get(email=email)
    #         if user.is_superuser:
    #             msg = {"message": f"{user.username} is already a superuser"}
    #             return Response(msg, status=status.HTTP_400_BAD_REQUEST)
    #         if not user.is_superuser:
    #             user.is_superuser = True
    #             user.is_staff = True
    #             user.save()
    #             subject = " expense notification"
    #             email_body = f"Hi  {user.username}, {email} has pointed as admin."
    #             email_data_to_send = {'subject': subject, 'body': email_body, 'to_email': user.email}
    #             Util.send_email(email_data_to_send)
    #             res = {
    #                 "message": f"{user.username} is now admin"
    #             }
    #             return Response(res, status=status.HTTP_200_OK)
    #
    #     else:
    #         if email is None:
    #             res = {"message": "please provide email and try again"},
    #             return Response(res, status=status.HTTP_400_BAD_REQUEST)
    #         if email:
    #             res = {"message": f"user with {email} email does not exist "}
    #             return Response(res, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmail(views.APIView):
    serializer_class = serializers.EmailVerificationSerializer
    renderer_classes = (UserRender,)
    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Description")

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
                subject = "Thank you!"
                email_body = f"Thank you for registering with us  {user.username}, \n\n" \
                             f"we love to have you in expense group."
                email_data_to_send = {'subject': subject, 'body': email_body, 'to_email': user.email}
                Util.send_email(email_data_to_send)

            return Response({'email': 'successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'activation link expired'}, status=status.HTTP_400_BAD_REQUEST)

        except jwt.exceptions.DecodeError:
            return Response({'error': 'invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(generics.GenericAPIView):
    """ Log in user with email and password"""
    serializer_class = serializers.LoginSerializer
    renderer_classes = (UserRender,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = serializers.ResetPasswordRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            relativelink = reverse('authentication:password-reset-confirm',
                                   kwargs={'uidb64': uidb64, 'token': token})
            domain = get_current_site(request=request).domain
            absurl = f'http://{domain}{relativelink}'
            subject = "Rest  Your password"
            email_body = f"Hello,Use link below to reset your password " \
                         f"\n{absurl}"
            email_data_to_send = {'subject': subject, 'body': email_body, 'to_email': user.email}
            Util.send_email(email_data_to_send)

        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPIView(generics.GenericAPIView):
    serializer_class = serializers.ResetPasswordRequestSerializer

    @staticmethod
    def get(request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new one'},
                                status=status.HTTP_401_UNAUTHORIZED)
            return Response({'success': True,
                             'message': 'Credentials Valid',
                             'uidb64': uidb64,
                             'token': token
                             }, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError:
            return Response({'error': 'Token is not valid, please request a new one'},
                            status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = serializers.SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'password reset success'}, status=status.HTTP_200_OK)


class MakeSuperuser(generics.GenericAPIView):
    """CREATE SUPERUSER"""
    serializer_class = serializers.MakeSuperUserSerializer
    permission_classes = (permissions.IsAdminUser,)
    renderer_classes = (UserRender,)

    def patch(self, request):
        data = request.data
        email = data['email']
        serializer = self.serializer_class(data=data)
        user = User.objects.get(email=email)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True,
                         'message': f' {user.username} is now a superuser '},
                        status=status.HTTP_200_OK)
