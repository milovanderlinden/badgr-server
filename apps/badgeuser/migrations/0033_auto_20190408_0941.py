# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2019-04-08 16:41
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('badgeuser', '0032_auto_20190327_0246'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='badgeuser',
            options={'permissions': (('view_issuer_tab', 'User can view Issuer tab in front end'), ('view_management_tab', 'User can view Management dashboard'), ('has_faculty_scope', 'User has faculty scope'), ('has_institution_scope', 'User has institution scope'), ('ui_issuer_add', 'User can add issuer in front end')), 'verbose_name': 'badge user', 'verbose_name_plural': 'badge users'},
        ),
    ]
