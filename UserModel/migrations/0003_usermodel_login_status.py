# Generated by Django 2.2.5 on 2019-10-22 08:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('UserModel', '0002_auto_20191021_1444'),
    ]

    operations = [
        migrations.AddField(
            model_name='usermodel',
            name='login_status',
            field=models.BooleanField(default=False, null=True),
        ),
    ]