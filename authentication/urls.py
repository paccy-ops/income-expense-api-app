from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from authentication import views

app_name = "authentication"

urlpatterns = [
    path('register/', views.RegisterView.as_view(), name="register"),
    path('make-superuser/', views.MakeSuperuser.as_view(), name="make-superuser"),
    path('login/', views.LoginAPIView.as_view(), name="login"),
    path('email-verify/', views.VerifyEmail.as_view(), name="email-verify"),
    path('password-reset-email/', views.RequestPasswordResetEmail.as_view(), name="request-reset-email"),
    path('password-reset/<uidb64>/<token>/', views.PasswordTokenCheckAPIView.as_view(),
         name="password-reset-confirm"),
    path('password-reset-complete/', views.SetNewPasswordAPIView.as_view(),
         name="password-reset-complete"),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
