# Generated by Django 2.2.3 on 2020-01-21 09:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0026_auto_20200121_1711'),
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
        migrations.DeleteModel(
            name='Penalty',
        ),
    ]