# Generated by Django 2.1.1 on 2019-04-30 12:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('credits', '0005_auto_20190430_1052'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pending_redeem',
            name='transaction_id',
            field=models.CharField(default='AE8165B565F1', max_length=14),
        ),
        migrations.AlterField(
            model_name='pending_transactions',
            name='transaction_id',
            field=models.CharField(default='ADDDA197815A', max_length=14),
        ),
    ]
