# -*- coding: utf_8 -*-
"""Android Static Code Analysis."""

import logging
import os
from os.path import basename
import re
import shutil
import datetime
from pathlib import Path

import settings

from utils import (
    file_size,
    is_dir_exists,
    is_file_exists,
    md5,
)
from StaticAnalyzer.cert_analysis import (
    cert_info,
    get_hardcoded_cert_keystore,
)
from StaticAnalyzer.code_analysis import code_analysis
from StaticAnalyzer.converter import (
    apk_2_java,
    dex_2_smali,
)
from StaticAnalyzer.db_interaction import (
    get_context_from_analysis,
)
from StaticAnalyzer.icon_analysis import (
    get_icon,
)
from StaticAnalyzer.manifest_analysis import (
    get_manifest,
    manifest_analysis,
    manifest_data,
)
from xapk import handle_xapk
from StaticAnalyzer.shared_func import (
    hash_gen,
    score,
    unzip,
    html_and_pdf,
)

from StaticAnalyzer.dvm_permissions_cn import DVM_PERMISSIONS
from androguard.core.bytecodes import apk


logger = logging.getLogger(__name__)

def static_analyzer_local(filepath, outpath = None, category = -1):
    """Do static analysis on an request and save to db."""
    try:
        filename = os.path.basename(filepath)
        typ = os.path.splitext(filename)[1][1:].lower()
        checksum = md5(filepath)
        
        logger.info("static_analyzer typ:%s checksum:%s filepath:%s", str(typ), checksum, filepath)
        # Input validation
        app_dic = {}
        match = re.match('^[0-9a-f]{32}$', checksum)
        nowtime = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        workspace = checksum[0:8] + '_' + nowtime
        if (match
                and filename.endswith(('.apk', '.xapk', '.zip'))
                and typ in ['zip', 'apk', 'xapk']):
            app_dic['dir'] = Path(settings.BASE_DIR)  # BASE DIR
            app_dic['app_name'] = filepath  # APP ORGINAL NAME
            app_dic['md5'] = checksum  # MD5
            # APP DIRECTORY
            if (outpath == None or len(outpath) == 0):
                app_dic['app_dir'] = Path(settings.UPLD_DIR) / workspace
            else:
                app_dic['app_dir'] = Path(outpath) / workspace
            app_dic['tools_dir'] = app_dic['dir'] / 'tools'
            app_dic['tools_dir'] = app_dic['tools_dir'].as_posix()

            # Create work folder
            if not os.path.exists(app_dic['app_dir']):
                os.makedirs(app_dic['app_dir'])

            print("dir:%s app_dir:%s tools_dir:%s"%(app_dic['dir'], app_dic['app_dir'], app_dic['tools_dir']))
            logger.info('Starting Analysis on : %s', app_dic['app_name'])
            print(app_dic)

            if typ == 'xapk':
                # Handle XAPK
                # Base APK will have the MD5 of XAPK
                res = handle_xapk(app_dic)
                if not res:
                    raise Exception('Invalid XAPK File')
                typ = 'apk'
            if typ == 'apk':
                app_dic['app_file'] = filename  # NEW FILENAME
                app_dic['app_path'] = (
                    app_dic['app_dir'] / app_dic['app_file']).as_posix()
                # Copy file
                shutil.copyfile(filepath, app_dic['app_path'])
                
                app_dic['app_dir'] = app_dic['app_dir'].as_posix() + '/'
                # ANALYSIS BEGINS
                app_dic['size'] = str(file_size(app_dic['app_path'])) + 'MB'  # FILE SIZE
                app_dic['sha1'], app_dic[
                    'sha256'] = hash_gen(app_dic['app_path'])
                app_dic['files'] = unzip(
                    app_dic['app_path'], app_dic['app_dir'])
                logger.info('APK Extracted')
                if not app_dic['files']:
                    # Can't Analyze APK, bail out.
                    msg = 'APK file is invalid or corrupt'
                    logger.error(msg)
                app_dic['certz'] = get_hardcoded_cert_keystore(app_dic['files'])
                # Manifest XML
                mani_file, mani_xml = get_manifest(
                    app_dic['app_path'],
                    app_dic['app_dir'],
                    app_dic['tools_dir'],
                    '',
                    True,
                )
                app_dic['manifest_file'] = mani_file
                app_dic['parsed_xml'] = mani_xml

                # get app_name
                app_dic['real_name'] = get_app_name(
                    app_dic['app_path'],
                    app_dic['app_dir'],
                    app_dic['tools_dir'],
                    True,
                )

                # Get icon
                res_path = os.path.join(app_dic['app_dir'], 'res')
                app_dic['icon_hidden'] = True
                # Even if the icon is hidden, try to guess it by the
                # default paths
                app_dic['icon_found'] = False
                app_dic['icon_path'] = ''
                # TODO: Check for possible different names for resource
                # folder?
                if os.path.exists(res_path):
                    icon_dic = get_icon(
                        app_dic['app_path'], res_path)
                    if icon_dic:
                        app_dic['icon_hidden'] = icon_dic['hidden']
                        app_dic['icon_found'] = bool(icon_dic['path'])
                        app_dic['icon_path'] = icon_dic['path']

                # Set Manifest link
                app_dic['mani'] = ('../manifest_view/?md5='
                                    + app_dic['md5']
                                    + '&type=apk&bin=1')
                man_data_dic = manifest_data(app_dic['parsed_xml'])
                man_an_dic = manifest_analysis(
                    app_dic['parsed_xml'],
                    man_data_dic,
                    '',
                    app_dic['app_dir'],
                )
                cert_dic = cert_info(
                    app_dic['app_dir'],
                    app_dic['app_file'])

                apk_2_java(app_dic['app_path'], app_dic['app_dir'],
                            app_dic['tools_dir'])

                dex_2_smali(app_dic['app_dir'], app_dic['tools_dir'])

                code_an_dic = code_analysis(
                    app_dic['app_dir'],
                    'apk',
                    app_dic['manifest_file'])
                    
                permissions = man_an_dic['permissons']
                api_permissions = code_an_dic['api_permissions']
                manifest_permissions = DVM_PERMISSIONS['MANIFEST_PERMISSION']
                # print("*************permissions *&& api_permissions*************")
                # print(permissions)
                # print("**************************")
                # print(api_permissions)
                # print("*************permissions *&& api_permissions*************")
                for permission in permissions:
                    # print(permission)
                    # print(permissions[permission])
                    if permission in api_permissions:
                        permissions[permission]['use'] = True
                        permissions[permission]['suggest'] = ''
                    else:
                        permissions[permission]['use'] = False
                        permissions[permission]['suggest'] = '您在 AndroidManifest.xml 中配置了%s权限，但是并未使用到该权限相关 API，建议您从配置清单删除该权限'%permission
                for permission in api_permissions:
                    per_info = api_permissions[permission]['metadata']
                    # print(per_info)
                    name = per_info['name']
                    if not permission in permissions:
                        permissions[permission] = {}
                        permissions[permission]['status'] = manifest_permissions[name][0]
                        permissions[permission]['info'] = manifest_permissions[name][1]
                        permissions[permission]['description'] = manifest_permissions[name][2]
                        permissions[permission]['use'] = True
                        permissions[permission]['suggest'] = '您使用了该权限相关 API, 但未在 AndroidManifest.xml 中配置，建议删除相关 API 调用，或者添加该权限配置'

                # Copy App icon
                copy_icon(app_dic['md5'], app_dic['icon_path'])
                app_dic['zipped'] = 'apk'

                context = get_context_from_analysis(
                    app_dic,
                    man_data_dic,
                    man_an_dic,
                    code_an_dic,
                    cert_dic,
                )

                context['average_cvss'], context[
                    'security_score'] = score(context['code_analysis'])

                rst_name = os.path.join(app_dic['app_dir'], checksum[0:8])
                write_to_file(context, app_dic['app_dir'], rst_name)
                write_to_html_and_pdf(context, rst_name)
                return context
            else:
                err = ('Only APK Source code supported now!')
                logger.error(err)
        else:
            msg = 'Hash match failed or Invalid file extension or file type'
            logger.error(msg)

    except Exception as excep:
        logger.exception('Error Performing Static Analysis')
        msg = str(excep)
        exp = excep.__doc__
        logger.error(msg)


def write_to_file(context, dir, rst_name):
    if (context == None):
        return
    jsonname = os.path.join(dir, rst_name + '.json')
    logger.info("Generating json Report to:%s"%jsonname)
    out = open(jsonname, mode = 'w', encoding = 'utf-8-sig')
    out.write(str(context))
    out.close

def write_to_html_and_pdf(context, rst_name):
    htmlname = rst_name + '.html'
    pdfname = rst_name + '.pdf'
    html_and_pdf(context, htmlname, pdfname)


def is_android_source(app_dir):
    """Detect Android Source and IDE Type."""
    # Eclipse
    man = os.path.isfile(os.path.join(app_dir, 'AndroidManifest.xml'))
    src = os.path.exists(os.path.join(app_dir, 'src/'))
    if man and src:
        return 'eclipse', True
    # Studio
    man = os.path.isfile(
        os.path.join(app_dir, 'app/src/main/AndroidManifest.xml'),
    )
    java = os.path.exists(os.path.join(app_dir, 'app/src/main/java/'))
    kotlin = os.path.exists(os.path.join(app_dir, 'app/src/main/kotlin/'))
    if man and (java or kotlin):
        return 'studio', True
    return None, False


def valid_source_code(app_dir):
    """Test if this is an valid source code zip."""
    try:
        logger.info('Detecting source code type')
        ide, is_and = is_android_source(app_dir)
        if ide:
            return ide, is_and
        # Relaxed Android Source check, one level down
        for x in os.listdir(app_dir):
            obj = os.path.join(app_dir, x)
            if not is_dir_exists(obj):
                continue
            ide, is_and = is_android_source(obj)
            if ide:
                move_to_parent(obj, app_dir)
                return ide, is_and
        # iOS Source
        xcode = [f for f in os.listdir(app_dir) if f.endswith('.xcodeproj')]
        if xcode:
            return 'ios', True
        # Relaxed iOS Source Check
        for x in os.listdir(app_dir):
            obj = os.path.join(app_dir, x)
            if not is_dir_exists(obj):
                continue
            if [f for f in os.listdir(obj) if f.endswith('.xcodeproj')]:
                return 'ios', True
        return '', False
    except Exception:
        logger.exception('Identifying source code from zip')


def move_to_parent(inside, app_dir):
    """Move contents of inside to app dir."""
    for x in os.listdir(inside):
        full_path = os.path.join(inside, x)
        shutil.move(full_path, app_dir)
    shutil.rmtree(inside)


def copy_icon(md5, icon_path=''):
    """Copy app icon."""
    try:
        # Icon
        icon_path = icon_path.encode('utf-8')
        if icon_path:
            if os.path.exists(icon_path):
                shutil.copy2(icon_path, os.path.join(
                    settings.DWD_DIR, md5 + '-icon.png'))
    except Exception:
        logger.exception('Generating Downloads')


def get_app_name(app_path, app_dir, tools_dir, is_apk):
    """Get app name."""
    print("get_app_name app_path:%s exits:%s app_dir:%s tools_dir:%s is_apk:%s"%(app_path, str(os.path.exists(app_path)), app_dir, tools_dir, str(is_apk)))
    if is_apk:
        a = apk.APK(app_path)
        real_name = a.get_app_name()
        return real_name
    else:
        strings_path = os.path.join(app_dir,
                                    'app/src/main/res/values/')
        eclipse_path = os.path.join(app_dir,
                                    'res/values/')
        if os.path.exists(strings_path):
            strings_dir = strings_path
        elif os.path.exists(eclipse_path):
            strings_dir = eclipse_path
        else:
            strings_dir = ''
    if not os.path.exists(strings_dir):
        logger.warning('Cannot find values folder.')
        return ''
    return get_app_name_from_values_folder(strings_dir)


def get_app_name_from_values_folder(values_dir):
    """Get all the files in values folder and checks them for app_name."""
    files = [f for f in os.listdir(values_dir) if
             (os.path.isfile(os.path.join(values_dir, f)))
             and (f.endswith('.xml'))]
    for f in files:
        # Look through each file, searching for app_name.
        app_name = get_app_name_from_file(os.path.join(values_dir, f))
        if app_name:
            return app_name  # we found an app_name, lets return it.
    return ''  # Didn't find app_name, returning empty string.


def get_app_name_from_file(file_path):
    """Looks for app_name in specific file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = f.read()

    app_name_match = re.search(r'<string name=\"app_name\">(.*)</string>',
                               data)

    if (not app_name_match) or (len(app_name_match.group()) <= 0):
        # Did not find app_name in current file.
        return ''

    # Found app_name!
    return app_name_match.group(app_name_match.lastindex)
