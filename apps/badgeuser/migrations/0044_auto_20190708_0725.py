# -*- coding: utf-8 -*-
# Generated by Django 1.11.22 on 2019-07-08 14:25
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('badgeuser', '0043_termsagreement_valid'),
    ]

    operations = [
        migrations.AlterField(
            model_name='termsagreement',
            name='valid',
            field=models.BooleanField(default=True),
        ),
    ]
