# Generated by Django 2.1.4 on 2019-04-14 05:20

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('registration', '0005_movie'),
    ]

    operations = [
        migrations.CreateModel(
            name='booking_history',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('movie_name', models.CharField(max_length=100)),
                ('movie_release_date', models.DateField()),
                ('movie_language', models.CharField(max_length=100)),
                ('theatre_name', models.CharField(max_length=50)),
                ('adressline1', models.CharField(max_length=50)),
                ('adressline2', models.CharField(max_length=50)),
                ('city', models.CharField(max_length=50)),
                ('state', models.CharField(max_length=50)),
                ('pincode', models.CharField(max_length=6)),
                ('screen_no', models.CharField(max_length=5)),
                ('show_timings', models.TimeField()),
                ('show_date', models.DateField()),
                ('seat_no', models.CharField(max_length=50)),
                ('price', models.CharField(max_length=100)),
                ('date_and_time_of_booking', models.DateTimeField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='theatre',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('theatre_name', models.CharField(max_length=50)),
                ('adressline1', models.CharField(max_length=50)),
                ('adressline2', models.CharField(max_length=50)),
                ('city', models.CharField(max_length=50)),
                ('state', models.CharField(max_length=50)),
                ('pincode', models.CharField(max_length=6)),
                ('screen_no', models.CharField(max_length=5)),
                ('seat_string', models.TextField()),
                ('theatre_rating', models.CharField(max_length=50)),
                ('now_playing', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='now_playing', to='registration.movie')),
                ('up_coming', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='up_coming', to='registration.movie')),
            ],
        ),
        migrations.CreateModel(
            name='ticket_price_and_time',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('show_timings', models.TimeField()),
                ('date', models.DateField()),
                ('seat_class', models.CharField(max_length=50)),
                ('price', models.CharField(max_length=100)),
                ('theatre_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='registration.theatre')),
            ],
        ),
    ]