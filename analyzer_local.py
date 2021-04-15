# -*- coding: utf_8 -*-
import os
import sys

import django

def main():
    argc = len(sys.argv)
    if (argc < 2):
        return

    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
    django.setup()

    print(sys.argv)
    if (argc >= 2):
        filename = sys.argv[1]
    outpath = None
    if (argc > 2):
        outpath = sys.argv[2]

    from StaticAnalyzer.static_analyzer import static_analyzer_local
    static_analyzer_local(filename, outpath)


if __name__ == "__main__" :
    result = main()
    sys.exit(result)