# -*- coding: utf-8 -*-
# Generated by Django 1.11.20 on 2019-08-27 18:54
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('signing', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='symmetrickey',
            options={'permissions': (('may_sign_assertions', 'User may sign assertions'),)},
        ),
    ]