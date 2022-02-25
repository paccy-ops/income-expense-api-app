from rest_framework import serializers
from expenses.models import Expense


class ExpenseSerializer(serializers.ModelSerializer):
    id = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Expense
        fields = ['id', 'amount', 'category', 'description', 'date']

    @staticmethod
    def get_id(obj):
        return obj.id
