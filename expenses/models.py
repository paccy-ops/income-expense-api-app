from django.conf import settings
from django.db import models


# Create your models here.

class Expense(models.Model):
    CATEGORY_OPTION = [
        ('ONLINE_SERVICES', 'ONLINE_SERVICES'),
        ('TRAVEL', 'TRAVEL'),
        ('FOOD', 'FOOD'),
        ('RENT', 'RENT'),
        ('OTHERS', 'OTHERS'),
    ]
    category = models.CharField(choices=CATEGORY_OPTION, max_length=255)
    amount = models.DecimalField(max_digits=10, decimal_places=2, max_length=255)
    description = models.TextField()
    owner = models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    date = models.DateField(null=False, blank=False)

    class Meta:
        # indexes = [
        #     models.Index(fields=['category'])
        # ]
        ordering = ('-date',)
        db_table = "expenses"
        # order_with_respect_to = 'amount'
        # verbose_name_plural = 'expenses'

    def __str__(self):
        return str(self.owner)
