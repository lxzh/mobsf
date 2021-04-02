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
from StaticAnalyzer.db_interaction import (get_context_from_db_entry as adb)

import MalwareAnalyzer.views.VirusTotal as VirusTotal
import settings

from utils import (
    upstream_proxy,
)

from templates import get_template as get_template1

from StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
)

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
        # android_static_db = StaticAnalyzerAndroid.objects.filter(
        #     MD5=checksum)
        # context = handle_pdf_android(android_static_db)

        template = get_pdf_template_android()    # Django template
        # template = get_pdf_template_android1() # jinja2 template
        # Do VT Scan only on binaries
        context['virus_total'] = None
        context['average_cvss'], context['security_score'] = score(context['code_analysis'])
        checksum = context['md5']
        ext = os.path.splitext(context['file_name'].lower())[1]
        if settings.VT_ENABLED and ext != '.zip':
            app_bin = os.path.join(
                settings.UPLD_DIR,
                checksum + '/',
                checksum + ext)
            vt = VirusTotal.VirusTotal()
            context['virus_total'] = vt.get_result(app_bin, checksum)
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

def handle_pdf_android(static_db):
    logger.info(
        'Fetching data from DB for '
        'PDF Report Generation (Android)')
    context = adb(static_db)
    context['average_cvss'], context[
        'security_score'] = score(context['code_analysis'])
    if context['file_name'].lower().endswith('.zip'):
        logger.info('Generating PDF report for android zip')
    else:
        logger.info('Generating PDF report for android apk')
    return context

# 注册 template 自定义过滤器
@register.filter
def key(d, key_name):
    """To get dict element by key name in template."""
    return d.get(key_name)

def get_pdf_template_android():
    template_path = 'pdf/android_report.html'
    template = get_template(template_path)
    return template

def get_pdf_template_android1():
    # template_path = 'pdf/android_report.html'
    # if context['file_name'].lower().endswith('.zip'):
    #     logger.info('Generating PDF report for android zip')
    #     template = get_template(template_path)
    # else:
    #     logger.info('Generating PDF report for android apk')
    #     template = get_template(template_path)

    pdf_path =  os.path.join(settings.BASE_DIR, 'templates', 'pdf', 'android_report.html')
    f = open(pdf_path, mode = 'r', encoding='utf-8')
    template_str = f.read()
    f.close()

    params = {}
    # params['BACKEND'] = 'django.template.backends.django.DjangoTemplates'
    params['OPTIONS'] = {}
    params['NAME'] = ''
    params['DIRS'] = os.path.join(settings.BASE_DIR, 'templates')
    params['APP_DIRS'] = True
    temp = DjangoTemplates(params)
    # template = temp.get_template(temp_name)
    template = temp.from_string(template_str)

    return template

def get_pdf_template_android2():
    template = get_template1('pdf/android_report.html')
    return template


def url_n_email_extract(dat, relative_path):
    """Extract URLs and Emails from Source Code."""
    urls = []
    emails = []
    urllist = []
    url_n_file = []
    email_n_file = []
    # URLs Extraction My Custom regex
    pattern = re.compile(
        (
            r'((?:https?://|s?ftps?://|'
            r'file://|javascript:|data:|www\d{0,3}[.])'
            r'[\w().=/;,#:@?&~*+!$%\'{}-]+)'
        ),
        re.UNICODE)
    urllist = re.findall(pattern, dat)
    uflag = 0
    for url in urllist:
        if url not in urls:
            urls.append(url)
            uflag = 1
    if uflag == 1:
        url_n_file.append(
            {'urls': urls, 'path': escape(relative_path)})

    # Email Extraction Regex
    regex = re.compile(r'[\w.-]{1,20}@[\w-]{1,20}\.[\w]{2,10}')
    eflag = 0
    for email in regex.findall(dat.lower()):
        if (email not in emails) and (not email.startswith('//')):
            emails.append(email)
            eflag = 1
    if eflag == 1:
        email_n_file.append(
            {'emails': emails, 'path': escape(relative_path)})
    return urllist, url_n_file, email_n_file


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


def open_firebase(url):
    # Detect Open Firebase Database
    try:
        purl = urlparse(url)
        base_url = '{}://{}/.json'.format(purl.scheme, purl.netloc)
        proxies, verify = upstream_proxy('https')
        headers = {
            'User-Agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1)'
                           ' AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/39.0.2171.95 Safari/537.36')}
        resp = requests.get(base_url, headers=headers,
                            proxies=proxies, verify=verify)
        if resp.status_code == 200:
            return base_url, True
    except Exception:
        logger.warning('Open Firebase DB detection failed.')
    return url, False


def firebase_analysis(urls):
    # Detect Firebase URL
    firebase_db = []
    logger.info('Detecting Firebase URL(s)')
    for url in urls:
        if 'firebaseio.com' in url:
            returl, is_open = open_firebase(url)
            fbdic = {'url': returl, 'open': is_open}
            if fbdic not in firebase_db:
                firebase_db.append(fbdic)
    return firebase_db


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
