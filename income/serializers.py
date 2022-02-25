from rest_framework import serializers
from income.models import Income


class IncomeSerializer(serializers.ModelSerializer):
    id = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Income
        fields = ['id', 'amount', 'source', 'description', 'date']

    @staticmethod
    def get_id(obj):
        return obj.id
