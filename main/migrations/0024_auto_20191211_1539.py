# Generated by Django 2.2.3 on 2019-12-11 07:39

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0023_auto_20191127_1110'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Audit',
        ),
        migrations.DeleteModel(
            name='Penalty',
        ),
    ]