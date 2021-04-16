# -*- coding: utf_8 -*-
import logging

import settings
from django.db.models import QuerySet
from utils import python_dict, python_list

"""Module holding the functions for the db."""


logger = logging.getLogger(__name__)


def get_context_from_analysis(app_dic,
                              man_data_dic,
                              man_an_dic,
                              code_an_dic,
                              cert_dic) -> dict:
    """Get the context for APK/ZIP from analysis results."""
    try:
        context = {
            'title':                'Static Analysis',
            'version':              settings.GEESF_VER,
            'file_name':            app_dic['app_name'],
            'app_name':             app_dic['real_name'],
            'app_type':             app_dic['zipped'],
            'size':                 app_dic['size'],
            'md5':                  app_dic['md5'],
            'sha1':                 app_dic['sha1'],
            'sha256':               app_dic['sha256'],
            'package_name':         man_data_dic['packagename'],
            'main_activity':        man_data_dic['mainactivity'],
            'exported_activities':  man_an_dic['exported_act'],
            'browsable_activities': python_dict(man_an_dic['browsable_activities']),
            'activities':           python_list(man_data_dic['activities']),
            'receivers':            python_list(man_data_dic['receivers']),
            'providers':            python_list(man_data_dic['providers']),
            'services':             python_list(man_data_dic['services']),
            'libraries':            python_list(man_data_dic['libraries']),
            'target_sdk':           man_data_dic['target_sdk'],
            'max_sdk':              man_data_dic['max_sdk'],
            'min_sdk':              man_data_dic['min_sdk'],
            'version_name':         man_data_dic['androvername'],
            'version_code':         man_data_dic['androver'],
            'icon_hidden':          app_dic['icon_hidden'],
            'icon_found':           app_dic['icon_found'],
            'permissions':          python_dict(man_an_dic['permissons']),
            'certificate_analysis': python_dict(cert_dic),
            'manifest_analysis':    python_list(man_an_dic['manifest_anal']),
            'network_security':     python_list(man_an_dic['network_security']),
            'file_analysis':        python_list(app_dic['certz']),
            'android_api':          python_dict(code_an_dic['api']),
            'code_analysis':        python_dict(code_an_dic['findings']),
            'files':                python_list(app_dic['files']),
            'exported_count':       python_dict(man_an_dic['exported_cnt']),
        }
        return context
    except Exception:
        logger.exception('Rendering to Template')