# -*- coding: utf-8 -*-
# Generated by Django 1.11.22 on 2019-07-05 11:07
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('badgeuser', '0040_termsversion_terms_and_conditions_template'),
    ]

    operations = [
        migrations.AddField(
            model_name='termsversion',
            name='accepted_Terms_and_conditions_hash',
            field=models.CharField(max_length=32, null=True, verbose_name='Term and conditions hash'),
        ),
    ]
