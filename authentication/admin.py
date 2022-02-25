from django.contrib import admin

from authentication.models import User
from expenses.models import Expense
from income.models import Income


# Register your models here.
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['username', 'email', 'is_active', 'create_at']
    list_editable = ['is_active']
    list_per_page = 3
    search_fields = ['email']


@admin.register(Income)
class IncomeAdmin(admin.ModelAdmin):
    list_display = ['owner', 'amount', 'date', 'source']
    list_filter = ['date']
    list_editable = ['amount', 'source']
    search_fields = ['description']
    list_per_page = 5
    date_hierarchy = 'date'


@admin.register(Expense)
class ExpenseAdmin(admin.ModelAdmin):
    list_display = ['owner', 'amount', 'date', 'category']
    list_filter = ['date']
    list_editable = ['amount', 'category']
    search_fields = ['description']
    list_per_page = 5
    date_hierarchy = 'date'
