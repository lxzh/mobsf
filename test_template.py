# -*- coding: utf_8 -*-
import os
import django
from django import template
from django.conf import settings as djs
from django.conf import global_settings
from django.template import engine
from django.template.backends.django import DjangoTemplates

# import settings
import settings


print(settings.TEMPLATES)
print(global_settings.TEMPLATES)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
# djs.configure()
django.setup()
print(global_settings.TEMPLATES)

# eg = engine.Engine()
# print(eg.find_template('pdf/android_report.html', os.path.join(BASE_DIR, 'templates')))

pdf_path =  os.path.join(settings.BASE_DIR, 'templates', 'pdf', 'android_report.html')
f = open(pdf_path, mode = 'r')
template_str = f.read()
f.close()
# print(template_str)

temp_name = 'pdf/android_report.html'
params = {}
# params['BACKEND'] = 'django.template.backends.django.DjangoTemplates'
params['OPTIONS'] = {}
params['NAME'] = ''
params['DIRS'] = os.path.join(settings.BASE_DIR, 'templates')
params['APP_DIRS'] = True
temp = DjangoTemplates(params)
# template = temp.get_template(temp_name)
template = temp.from_string(template_str)

print(template)
