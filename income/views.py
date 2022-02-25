from rest_framework import generics
from income import serializers
from income.models import Income
from rest_framework import permissions
from income.permissions import IsOwner


# Create your views here.
class IncomeListAPIView(generics.ListCreateAPIView):
    """Get list of income"""
    serializer_class = serializers.IncomeSerializer
    queryset = Income.objects.all()
    permission_classes = (permissions.IsAuthenticated,)

    def perform_create(self, serializer):
        return serializer.save(owner=self.request.user)

    def get_queryset(self):
        """QUERY LIST OF INCOME"""
        return self.queryset.filter(owner=self.request.user)


class IncomeDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = serializers.IncomeSerializer
    queryset = Income.objects.all()
    permission_classes = (permissions.IsAuthenticated, IsOwner)
    lookup_field = "id"

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user)
