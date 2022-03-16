from django.http import HttpResponsePermanentRedirect
from django.shortcuts import redirect
import jwt
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.utils.encoding import smart_str, smart_bytes, \
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
import os

# Create your views here.

class CustomerRedirect(HttpResponsePermanentRedirect):
    allowed_schema = [os.environ.get('APP_SCHEME'),'http','https']

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
        email = request.data['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            relativelink = reverse('authentication:password-reset-confirm',
                                   kwargs={'uidb64': uidb64, 'token': token})
            redirect_url = request.data.get('redirect_url','')
            domain = get_current_site(request=request).domain
            absurl = f'http://{domain}{relativelink}'
            subject = "Rest  Your password" 
            email_body = f"Hello,Use link below to reset your password " \
                         f"\n{absurl}?redirect_url={redirect_url}"
            email_data_to_send = {'subject': subject, 'body': email_body, 'to_email': user.email}
            Util.send_email(email_data_to_send)

        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPIView(generics.GenericAPIView):
    serializer_class = serializers.ResetPasswordRequestSerializer

    @staticmethod
    def get(request, uidb64, token):
        redirect_url = request.GET.get('redirect_url')
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                if len(redirect_url)>3:
                    return CustomerRedirect(redirect_url+'?token_valid=False')
                else:
                    return CustomerRedirect(os.environ.get("FRONTEND_URL",'')+'?token_valid=False')
                # return Response({'error': 'Token is not valid, please request a new one'},
                #                 status=status.HTTP_401_UNAUTHORIZED)
            if redirect_url and len(redirect_url)>3:
                return CustomerRedirect(redirect_url+f'?token_valid=True&?message=Credentials Valid&?uidb64={uidb64}&?token={token}')
            else:
                return CustomerRedirect(os.environ.get("FRONTEND_URL",'')+'?token_valid=False')
            # return Response({'success': True,
            #                  'message': 'Credentials Valid',
            #                  'uidb64': uidb64,
            #                  'token': token
            #                  }, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError:
            return CustomerRedirect(redirect_url+'?token_valid=False')
            # return Response({'error': 'Token is not valid, please request a new one'},
            #                 status=status.HTTP_401_UNAUTHORIZED)


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

class LogoutAPIView(generics.GenericAPIView):
      serializer_class = serializers.LogoutSerializer
      permission_class = (permissions.IsAuthenticated,)

      def post(self,request): 
          serializer = self.serializer_class(data=request.data)
          serializer.is_valid(raise_exception=True)
          serializer.save()

          return Response(status=status.HTTP_204_NO_CONTENT)

class AuthUserAPIView(generics.GenericAPIView):
    permission_class = (permissions.IsAuthenticated)
    def get(self,request):
        user = User.objects.get(pk=request.user.pk)
        serializer = serializers.RegisterSerializer(user)
        return Response(serializer.data)
