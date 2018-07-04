import sys
from getpass import getpass

from prettytable import PrettyTable

from .common import *
from .. import colors
from .. import config
from .. import global_vars


def process_download_packages():
    global_vars.problem = ProblemSession(config.polygon_url, None)
    global_vars.problem.download_all_packages()

def process_download_contest_packages(contestId):
    global_vars.problem = ProblemSession(config.polygon_url, None)
    global_vars.problem.download_contest_packages(contestId)


def add_parser(subparsers):
    parser_download_all_packages = subparsers.add_parser(
            'all_packages',
            help="Download all problem packages"
    )
    parser_download_all_packages.set_defaults(func=lambda options: process_download_packages())

    parser_download_contest_packages = subparsers.add_parser(
            'contest_packages',
            help="Download contest problem packages by contest-id"
    )
    parser_download_contest_packages.add_argument('contestId', help='Contest id to download packages for')
    parser_download_contest_packages.set_defaults(func=lambda options: process_download_contest_packages(options.contestId))

