#!/usr/bin/env python3

import argparse

from polyglot_detector import magic, scan, rules


def display_results(results: [(str, {})], indent=False):
    for result in results.items():
        if indent:
            print('\t', end='')
        print('%s: %s' % (result[0], result[1]))


def create_arg_parser():
    arg_parser = argparse.ArgumentParser(prog='polyglot-detector',
                                         description='A tool to detect polyglot in common formats')
    arg_parser.add_argument('files', type=str, nargs='+', help='File to scan')
    arg_parser.add_argument('-m', '--magic', dest='magic', action='store_true', help='Scan with libmagic')
    arg_parser.add_argument('--magic-file', dest='magic_file', type=str,
                            help='Specify the magic file to use. Require --magic')
    arg_parser.add_argument('-r', '--rules', dest='rules', type=str, help='File to load and store rules to speed up the process.')
    arg_parser.add_argument('-c', '--recompile', dest='recompile', action='store_true', help='Re-compile rules. '
                                                                                             'Require --rules')
    return arg_parser


def main():
    arg_parser = create_arg_parser()
    args = arg_parser.parse_args()

    # Configure libmagic
    if args.magic and args.magic_file is not None:
        magic.set_magic_file(args.magic_file)

    if args.rules:
        if args.recompile:
            rules.save(args.rules)
        else:
            rules.load_or_compile(args.rules)

    if len(args.files) == 1:
        display_results(scan(args.files[0], use_magic=args.magic))
    else:
        for filename in args.files:
            print('%s:' % filename)
            display_results(scan(filename, use_magic=args.magic), indent=True)


if __name__ == '__main__':
    main()
