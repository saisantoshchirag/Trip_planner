# Generated by Django 2.1.1 on 2019-04-06 07:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('credits', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pending_redeem',
            name='transaction_id',
            field=models.CharField(default='053E58202265', max_length=14),
        ),
        migrations.AlterField(
            model_name='pending_transactions',
            name='transaction_id',
            field=models.CharField(default='ADD2F1460CF2', max_length=14),
        ),
        migrations.AlterField(
            model_name='statement',
            name='amount',
            field=models.CharField(max_length=10),
        ),
    ]
