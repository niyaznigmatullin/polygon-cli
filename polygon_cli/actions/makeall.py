import sys
from getpass import getpass

from prettytable import PrettyTable

from .common import *
from .. import colors
from .. import config
from .. import global_vars


def get_login_password():
    if config.login:
        print('Using login %s from config' % config.login)
    else:
        print('Enter login:', end=' ')
        sys.stdout.flush()
        config.login = sys.stdin.readline().strip()
    if config.password:
        print('Using password from config')
    else:
        config.password = getpass('Enter password: ')


def process_discard():
    get_login_password()
    global_vars.problem = ProblemSession(config.polygon_url, None)
    global_vars.problem.login(config.login, config.password)
    global_vars.problem.discard_everything()

def process_download_packages():
    get_login_password()
    global_vars.problem = ProblemSession(config.polygon_url, None)
    global_vars.problem.login(config.login, config.password)
    global_vars.problem.download_all_packages()


def add_parser(subparsers):
    parser_discard = subparsers.add_parser(
            'discard_all',
            help="Discard all problem copies"
    )
    parser_discard.set_defaults(func=lambda options: process_discard())

    parser_download_packages = subparsers.add_parser(
            'all_packages',
            help="Download all problem packages"
    )
    parser_download_packages.set_defaults(func=lambda options: process_download_packages())
