# -*- coding: utf-8 -*-
# Generated by Django 1.11.13 on 2018-08-11 13:28
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('institution', '0001_initial'),
        ('badgeuser', '0021_auto_20180811_0443'),
    ]

    operations = [
        migrations.AddField(
            model_name='badgeuser',
            name='faculty',
            field=models.ManyToManyField(blank=True, to='institution.Faculty'),
        ),
    ]
