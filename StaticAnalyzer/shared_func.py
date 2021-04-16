# -*- coding: utf_8 -*-
"""
Shared Functions.

Module providing the shared functions for static analysis of iOS and Android
"""
import hashlib
import io
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import zipfile
from urllib.parse import urlparse
from pathlib import Path

import requests

from django.template.defaulttags import register
from django.template.loader import get_template
from django.utils import timezone
from django.utils.html import escape
from django.template.backends.django import DjangoTemplates

import settings

from utils import (
    upstream_proxy,
)

from templates import get_template as get_template1

logger = logging.getLogger(__name__)

try:
    import pdfkit
except ImportError:
    logger.warning(
        'wkhtmltopdf is not installed/configured properly.'
        ' PDF Report Generation is disabled')
logger = logging.getLogger(__name__)
ctype = 'application/json; charset=utf-8'


def hash_gen(app_path) -> tuple:
    """Generate and return sha1 and sha256 as a tuple."""
    try:
        logger.info('Generating Hashes')
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        block_size = 65536
        with io.open(app_path, mode='rb') as afile:
            buf = afile.read(block_size)
            while buf:
                sha1.update(buf)
                sha256.update(buf)
                buf = afile.read(block_size)
        sha1val = sha1.hexdigest()
        sha256val = sha256.hexdigest()
        return sha1val, sha256val
    except Exception:
        logger.exception('Generating Hashes')


def unzip(app_path, ext_path):
    logger.info('Unzipping')
    try:
        files = []
        with zipfile.ZipFile(app_path, 'r') as zipptr:
            for fileinfo in zipptr.infolist():
                filename = fileinfo.filename
                if not isinstance(filename, str):
                    filename = str(
                        filename, encoding='utf-8', errors='replace')
                files.append(filename)
                zipptr.extract(filename, ext_path)
        return files
    except Exception:
        logger.exception('Unzipping Error')
        if platform.system() == 'Windows':
            logger.info('Not yet Implemented.')
        else:
            logger.info('Using the Default OS Unzip Utility.')
            try:
                unzip_b = shutil.which('unzip')
                subprocess.call(
                    [unzip_b, '-o', '-q', app_path, '-d', ext_path])
                dat = subprocess.check_output([unzip_b, '-qq', '-l', app_path])
                dat = dat.decode('utf-8').split('\n')
                files_det = ['Length   Date   Time   Name']
                files_det = files_det + dat
                return files_det
            except Exception:
                logger.exception('Unzipping Error')


def html_and_pdf(context, htmlpath, pdfpath):
    try:
        template = get_pdf_template_android()    # Django template
        # Do VT Scan only on binaries
        context['average_cvss'], context['security_score'] = score(context['code_analysis'])
        checksum = context['md5']
        ext = os.path.splitext(context['file_name'].lower())[1]
        # Get Local Base URL
        proto = 'file://'
        host_os = 'nix'
        if platform.system() == 'Windows':
            proto = 'file:///'
            host_os = 'windows'
        context['base_url'] = proto + settings.BASE_DIR
        context['dwd_dir'] = proto + settings.DWD_DIR
        context['host_os'] = host_os
        context['timestamp'] = timezone.now()
        try:
            options = {
                'page-size': 'Letter',
                'quiet': '',
                'enable-local-file-access': '',
                'no-collate': '',
                'margin-top': '0.50in',
                'margin-right': '0.50in',
                'margin-bottom': '0.50in',
                'margin-left': '0.50in',
                'encoding': 'UTF-8',
                'custom-header': [
                    ('Accept-Encoding', 'gzip'),
                ],
                'no-outline': None,
            }
            # Added proxy support to wkhtmltopdf
            proxies, _ = upstream_proxy('https')
            if proxies['https']:
                options['proxy'] = proxies['https']

            html = template.render(context)
            logger.info("Generating Html Report to:%s"%htmlpath)
            write_to_file(html, htmlpath)
            # html = template.render(context).encode('utf-8')
            logger.info("Generating PDF Report to:%s"%pdfpath)
            pdfkit.from_string(html, pdfpath, options=options)
        except Exception as exp:
            logger.exception('Error Generating PDF Report:%s'%str(exp))
    except Exception as exp:
        logger.exception('Error Generating PDF Report%s'%str(exp))

def write_to_file(html, htmlpath):
    out = open(htmlpath, mode = 'w', encoding = 'utf-8-sig')
    out.write(html)
    out.close

# 注册 template 自定义过滤器
@register.filter
def key(d, key_name):
    """To get dict element by key name in template."""
    return d.get(key_name)

def get_pdf_template_android():
    template_path = 'pdf/android_report.html'
    template = get_template(template_path)
    return template

def score(findings):
    # Score Apps based on AVG CVSS Score
    cvss_scores = []
    avg_cvss = 0
    app_score = 100
    if findings!= None:
        for finding in findings.values():
            find = finding.get('metadata')
            if not find:
                # Hack to support iOS Binary Scan Results
                find = finding
            if find.get('cvss'):
                if find['cvss'] != 0:
                    cvss_scores.append(find['cvss'])
            if find['severity'] == 'high':
                app_score = app_score - 15
            elif find['severity'] == 'warning':
                app_score = app_score - 10
            elif find['severity'] == 'good':
                app_score = app_score + 5
    if cvss_scores:
        avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 1)
    if app_score < 0:
        app_score = 10
    elif app_score > 100:
        app_score = 100
    return avg_cvss, app_score

def find_java_source_folder(base_folder: Path):
    # Find the correct java/kotlin source folder for APK/source zip
    # Returns a Tuple of - (SRC_PATH, SRC_TYPE, SRC_SYNTAX)
    return next(p for p in [(base_folder / 'java_source',
                             'java', '*.java'),
                            (base_folder / 'app' / 'src' / 'main' / 'java',
                             'java', '*.java'),
                            (base_folder / 'app' / 'src' / 'main' / 'kotlin',
                             'kotlin', '*.kt'),
                            (base_folder / 'src',
                             'java', '*.java')]
                if p[0].exists())
