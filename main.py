#!/usr/bin/env python3

import argparse
from polyglot_detector import PolyglotLevel, scan


def create_arg_parser():
    arg_parser = argparse.ArgumentParser(prog='polyglot-detector',
                                         description='A tool to detect polyglot in common formats')
    arg_parser.add_argument('files', type=str, nargs='+', help='File to scan')
    return arg_parser


def display_results(results: [(str, PolyglotLevel)], indent=False):
    for result in results:
        if indent:
            print('\t', end='')
        print('- %s: %s' % (result[0], result[1]))


def main():
    arg_parser = create_arg_parser()
    args = arg_parser.parse_args()
    if len(args.files) == 1:
        display_results(scan(args.files[0]))
    else:
        for filename in args.files:
            print('%s:' % filename)
            display_results(scan(filename), indent=True)


if __name__ == '__main__':
    main()
