from rest_framework import generics
from expenses import serializers
from expenses.models import Expense
from rest_framework import permissions
from expenses.permissions import IsOwner


# Create your views here.
class ExpenseListAPIView(generics.ListCreateAPIView):
    """Get list of expenses"""
    serializer_class = serializers.ExpenseSerializer
    queryset = Expense.objects.all()
    permission_classes = (permissions.IsAuthenticated,)

    def perform_create(self, serializer):
        return serializer.save(owner=self.request.user)

    def get_queryset(self):
        """QUERY LIST OF EXPENSES"""
        return self.queryset.filter(owner=self.request.user)


class ExpenseDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = serializers.ExpenseSerializer
    queryset = Expense.objects.all()
    permission_classes = (permissions.IsAuthenticated, IsOwner)
    lookup_field = "id"

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user)
