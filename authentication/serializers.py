from django.contrib import auth
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.forms import ValidationError
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken
from authentication.models import User
from authentication.utils import Util
from rest_framework_simplejwt.tokens import TokenError


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    def validate(self, attrs):
        username = attrs.get('username', '')
        if not username.isalnum():
            raise serializers.ValidationError("The username should only contain alphanumeric character")
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=5)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.EmailField(max_length=255, min_length=5, read_only=True)
    tokens = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']
    def get_tokens(self,obj):
        user = User.objects.get(email=obj['email'])
        return{
            "access":user.tokens()['access'],
            "refresh":user.tokens()['refresh']
        }

    def validate(self, attrs):
        email = attrs['email']
        password = attrs['password']
        user = auth.authenticate(email=email, password=password)
        if not user:
            raise AuthenticationFailed("Invalid credentials, try again")
        elif not user.is_active:
            raise AuthenticationFailed("Account disabled,contact admin")
        elif not user.is_verified:
            raise AuthenticationFailed("Email is not  verified")
        attrs['email'] = user.email
        attrs['username'] = user.username
        attrs['tokens'] = user.tokens()

        return attrs


class ResetPasswordRequestSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(min_length=4)
    redirect_url = serializers.CharField(max_length=500,required=False)

    class Meta:
        model = User
        fields = ['email','redirect_url']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        model = User
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)
            user.set_password(password)
            user.save()
            return user
        except Exception:
            raise AuthenticationFailed('The reset link is invalid', 401)


class MakeSuperUserSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=1, write_only=True)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.get(email=email).DoesNotExist:
            raise AuthenticationFailed('ido')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            if user.is_superuser:
                raise AuthenticationFailed('user is already a superuser')
            user.is_superuser = True
            user.is_staff = True
            user.save()
            subject = " expense notification"
            email_body = f"Hi  {user.username}, {email} has pointed as admin."
            email_data_to_send = {'subject': subject, 'body': email_body, 'to_email': user.email}
            Util.send_email(email_data_to_send)
            return user

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()

        except TokenError:
            self.fail("bad token")
