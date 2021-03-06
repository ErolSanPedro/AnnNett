# Generated by Django 2.2.3 on 2019-11-26 01:45

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0003_auto_20190729_1328'),
    ]

    operations = [
        migrations.CreateModel(
            name='Penalty',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('lastaccessed', models.DateTimeField(default=django.utils.timezone.now)),
                ('penaltycount', models.IntegerField(default=0, null=True)),
                ('rulenum', models.IntegerField(default=0, null=True)),
                ('status', models.CharField(max_length=45)),
            ],
        ),
        migrations.RemoveField(
            model_name='audit',
            name='blacklistid',
        ),
        migrations.RemoveField(
            model_name='audit',
            name='id',
        ),
        migrations.AlterField(
            model_name='audit',
            name='sourceip',
            field=models.CharField(max_length=45, primary_key=True, serialize=False),
        ),
        migrations.DeleteModel(
            name='Blacklist',
        ),
    ]
