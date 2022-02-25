from django.urls import path
from expenses import views

app_name = 'expenses'
urlpatterns = [
    path('', views.ExpenseListAPIView.as_view(), name='expense-list'),
    path('<int:id>', views.ExpenseDetailAPIView.as_view(), name='expense-detail'),

]
