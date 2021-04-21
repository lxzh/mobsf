# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import logging
from pathlib import Path

import settings

from utils import filename_from_path
from sast_engine import (
    scan,
)

logger = logging.getLogger(__name__)


def code_analysis(app_dir, typ, manifest_file):
    """Perform the code analysis."""
    try:
        logger.info('Code Analysis Started')
        root = Path(settings.BASE_DIR) 
        code_rules = root / 'rules' / 'android_rules.yaml'
        api_rules  = root / 'rules' / 'android_apis.yaml'
        permission_rules = root / 'rules' / 'android_permission_apis.yaml'
        code_findings = {}
        api_findings = {}
        app_dir = Path(app_dir)
        if typ == 'apk':
            src = app_dir / 'java_source'
        elif typ == 'studio':
            src = app_dir / 'app' / 'src' / 'main' / 'java'
            kt = app_dir / 'app' / 'src' / 'main' / 'kotlin'
            if not src.exists() and kt.exists():
                src = kt
        elif typ == 'eclipse':
            src = app_dir / 'src'
        src = src.as_posix() + '/'
        skp = settings.SKIP_CLASS_PATH
        logger.info('Code Analysis Started on - %s',
                    filename_from_path(src))
        # Code and API Analysis
        code_findings = scan(
            code_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)
        api_findings = scan(
            api_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)
        permission_findings = scan(permission_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)
        logger.info('Finished Code Analysis')
        print("*************permission_findings*************")
        print(permission_findings)
        print("*************permission_findings*************")
        code_an_dic = {
            'api': api_findings,
            'findings': code_findings,
            'api_permissions': permission_findings,
        }
        return code_an_dic
    except Exception:
        logger.exception('Performing Code Analysis')
