# Generated by Django 4.0.2 on 2022-02-16 06:42

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('expenses', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelTable(
            name='expense',
            table='expenses',
        ),
    ]