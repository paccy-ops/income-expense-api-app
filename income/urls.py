from django.urls import path
from income import views

app_name = 'income'
urlpatterns = [
    path('', views.IncomeListAPIView.as_view(), name='income-list'),
    path('<int:id>', views.IncomeDetailAPIView.as_view(), name='income-detail'),

]
