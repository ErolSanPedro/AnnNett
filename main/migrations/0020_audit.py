# Generated by Django 2.2.3 on 2019-11-26 09:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0019_blacklist_penalty'),
    ]

    operations = [
        migrations.CreateModel(
            name='Audit',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('sourceip', models.CharField(max_length=45)),
                ('macaddress', models.CharField(max_length=45)),
                ('time', models.DateTimeField(null=True)),
            ],
        ),
    ]
