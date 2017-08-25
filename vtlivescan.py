#!/usr/bin/env python3
import os
import json
import logging
import hashlib
import requests
import subprocess
import multiprocessing
import logging.handlers
import inotify.adapters
import inotify.constants

def setup_dirs(basedir):
    if not(os.path.exists(basedir) and os.path.isdir(basedir)):
        os.mkdir(basedir)

def setup_logging(basedir):
    log_path = os.path.expanduser(basedir + '/app.log')
    logger = logging.getLogger()

    handler = logging.handlers.RotatingFileHandler(log_path, maxBytes=131072, backupCount=3)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

def get_config(basedir):
    config = {
        'paths': set(),
        'extensions': set()
    }

    with open(os.path.expanduser(basedir + '/config.json')) as data:
        user_config = json.load(data)

        if 'vt_api_key' in user_config and type(user_config['vt_api_key']) is str:
            config['vt_api_key'] = user_config['vt_api_key']
        else:
            raise Exception('Failed to find virustotal API key')

        if 'paths' in user_config and type(user_config['paths']) is list:
            for path in user_config['paths']:
                path = os.path.expanduser(path.encode())
                if not os.path.isabs(path):
                    logging.warn('"%s" is not an absolute path and was ignored' % (path,))
                elif not os.path.isdir(path):
                    logging.warn('"%s" is not a directory and was ignored' % (path,))
                else:
                    config['paths'].add(path)

        if not config['paths']:
            logging.info('Using default paths')
            config['paths'] = {os.path.expanduser('~/Downloads').encode()}

        if 'extensions' in user_config and type(user_config['extensions']) is list:
            for ext in user_config['extensions']:
                if ext[0] == '.':
                    ext = ext[1:]

                if ext == '':
                    continue

                config['extensions'].add(ext.lower())

        if not config['extensions']:
            logging.info('Using default extensions')
            config['extensions'] = {
                'exe', 'msi', 'dll', 'scr', 'cpl', 'apk', 'jar', 'swf', 'vbs',
                'wsf', 'zip', 'rar', 'iso', 'pdf', 'doc', 'xls', 'ppt', 'docm',
                'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'ppsm'
            }

    return config

def notify(title, message, icon='', expires=15):
    subprocess.call(['notify-send', title, message, '-t', str(expires * 1000), '-i', icon])

def check_file(path, vt_api_key):
    hash = hashlib.sha256()

    try:
        with open(path, 'rb') as f:
            while True:
                data = f.read(4096)
                if not data:
                    break

                hash.update(data)

        params = {
            'apikey': vt_api_key,
            'resource': hash.hexdigest()
        }

        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)

        if response.status_code != 200:
            notify('Malware check failed',
                   "Failed to check %s for malware, probably because the rate limits were exceeded."
                   % (path,),
                   'dialog-information')
        else:
            jsonresponse = response.json()

            if 'positives' in jsonresponse and 'total' in jsonresponse:
                positives = jsonresponse['positives']
                total = jsonresponse['total']

                for antivirus in jsonresponse['scans'].keys():
                    if jsonresponse['scans'][antivirus]['detected']:
                        virusname = jsonresponse['scans'][antivirus]['result']
                        break

                if positives > 0:
                    notify('Potential malware detected',
                           'File: %s\n'
                           'Malware family: %s (%s)\n'
                           'Detection Ratio: %i/%i (%f%%)'
                           % (path, virusname, antivirus, positives, total, 100 * positives/total),
                           'dialog-warning',
                           120)

    except requests.exceptions.RequestException as e:
        logging.warn('Unable to check file "' + path + '": ' + str(e))
    except IOError as e:
        logging.warn('Unable to read file "' + path + '": ' + str(e))

def monitor_dirs(paths, scan_exts, vt_api_key):
    watcher = inotify.adapters.InotifyTrees(paths=paths, mask=inotify.constants.IN_CLOSE_WRITE | inotify.constants.IN_MOVED_TO)

    try:
        for event in watcher.event_gen():
            if event is not None and event[0].mask in [inotify.constants.IN_CLOSE_WRITE, inotify.constants.IN_MOVED_TO]:
                filename = event[3].decode('utf-8')
                ext = os.path.splitext(filename)[1][1:].lower()

                if ext in scan_exts:
                    path = event[2].decode('utf-8') + '/' + filename
                    checker = multiprocessing.Process(target=check_file, args=(path, vt_api_key))
                    checker.start()
    finally:
        for path in paths:
            watcher.remove_watch(path)

basedir = os.path.expanduser('~/.vtlivescan')

setup_dirs(basedir)
setup_logging(basedir)

config = get_config(basedir)
monitor_dirs(list(config['paths']), config['extensions'], config['vt_api_key'])
