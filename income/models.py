from django.conf import settings
from django.db import models


# Create your models here.
class Income(models.Model):
    SOURCE_OPTION = [
        ('SALARY', 'SALARY'),
        ('BUSINESS', 'BUSINESS'),
        ('SIDE-HUSTLES', 'SIDE-HUSTLES'),
        ('OTHERS', 'OTHERS'),
    ]
    source = models.CharField(choices=SOURCE_OPTION, max_length=255)
    amount = models.DecimalField(max_digits=10, decimal_places=2, max_length=255)
    description = models.TextField()
    owner = models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    date = models.DateField(null=False, blank=False)

    class Meta:
        ordering = ('-date',)
        db_table = "income"
        # indexes = [
        #     models.Index(fields=['source'])
        # ]

    def __str__(self):
        return str(self.owner)
