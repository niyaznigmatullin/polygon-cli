from .common import *
import os

def process_import_problem_from_folder(directory):
    if not load_session():
        fatal('No session known. Use relogin or init first.')
    global_vars.problem.import_problem_from_folder(directory)
    save_session()

def add_parser(subparsers):
    parser_import_problem_from_folder = subparsers.add_parser(
            'import_folder',
            help="Imports problem from folder"
    )
    parser_import_problem_from_folder.add_argument('directory', help='The directory that is going to be imported. It has to contain `src` and `solutions` folders')
    parser_import_problem_from_folder.set_defaults(func=lambda options: process_import_problem_from_folder(options.directory))
