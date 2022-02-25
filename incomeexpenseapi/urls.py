"""incomeexpenseapi URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="expense  API",
        default_version='v1',
        description="An api for expenses",
        terms_of_service="https://youro/terms/",
        contact=openapi.Contact(email="pacifiquetwagirayesu@gmail.com"),
        license=openapi.License(name="Api License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('auth/', include('authentication.urls', namespace='authentication')),
    path('expenses/', include('expenses.urls', namespace='expenses')),
    path('income/', include('income.urls', namespace='income')),
    path('stats/', include('userstats.urls')),
]
