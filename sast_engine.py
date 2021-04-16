# -*- coding: utf_8 -*-
"""SAST engine."""
import logging
import collections

from libsast import Scanner

logger = logging.getLogger(__name__)


def scan(rule, extensions, paths, ignore_paths=None):
    """The libsast scan."""
    try:
        options = {
            'match_rules': rule,
            'match_extensions': extensions,
            'ignore_paths': ignore_paths,
            'show_progress': False}
        # print("Scanner")
        # print(rule)
        # print(extensions)
        # print(ignore_paths)
        # print(paths)
        scanner = Scanner(options, paths)
        res = scanner.scan()
        if res:
            return format_findings(res['pattern_matcher'], paths[0])
    except Exception:
        logger.exception('libsast scan')
    return {}


def format_findings(findings, root):
    """Format findings."""
    for details in findings.values():
        tmp_dict = {}
        print('**************************start')
        print(details)
        for file_meta in details['files']:
            file_meta['file_path'] = file_meta['file_path'].replace(root, '', 1)
            file_path = file_meta['file_path']
            start     = file_meta['match_lines'][0]
            end       = file_meta['match_lines'][1]
            match_lines = []
            if start == end:
                match_lines.append(start)
            else:
                exp_lines = []
                for i in range(start, end + 1):
                    exp_lines.append(i)
                # sort the matched line number
                match_lines = exp_lines
            if file_path not in tmp_dict:
                tmp_dict[file_path] = match_lines
            else:
                tmp_dict[file_path].extend(match_lines)
        details['files'] = tmp_dict
        print('**************************')
        print(details)
        print('**************************end')
    
    # sort the result with filepath
    for details in findings.values():
        tmp_dict = collections.OrderedDict()
        for key in sorted(details['files'].keys()):
            tmp_dict[key] = str(sorted(list(set(details['files'][key]))))
        details['files'] =  tmp_dict
    print(details)
    print('=========================')
    return findings
