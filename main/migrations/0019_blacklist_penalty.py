# Generated by Django 2.2.3 on 2019-11-26 09:38

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('main', '0018_auto_20191126_1714'),
    ]

    operations = [
        migrations.CreateModel(
            name='Blacklist',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('ipaddress', models.CharField(blank=True, max_length=45, null=True)),
                ('domain', models.CharField(blank=True, default='', max_length=500, null=True)),
                ('port', models.IntegerField(blank=True, default=80, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Penalty',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('lastaccessed', models.DateTimeField(default=django.utils.timezone.now)),
                ('penaltycount', models.IntegerField(default=0, null=True)),
                ('rulenum', models.IntegerField(default=0, null=True)),
                ('status', models.CharField(max_length=45)),
                ('ipaddress', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.Blacklist')),
            ],
        ),
    ]