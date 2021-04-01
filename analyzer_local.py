# -*- coding: utf_8 -*-
import os
import sys

from utils import md5

import settings
import django
from django.conf import settings as djs
from django.conf import global_settings
from django.utils.log import configure_logging

def main():
    if(len(sys.argv)!=2):
        return

    # djs.configure()
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
    django.setup()
    # configure_logging('logging.config.dictConfig', settings.LOGGING)
    global TEMPLATES
    TEMPLATES = settings.TEMPLATES

    filename = sys.argv[1]
    print(filename)

    typ = 'apk'

    md5sum = md5(filename)
    print(md5sum)

    rescan = 0

    from StaticAnalyzer.static_analyzer import static_analyzer_local
    static_analyzer_local(typ, md5sum, filename, rescan)


if __name__ == "__main__" :
    result = main()
    sys.exit(result)