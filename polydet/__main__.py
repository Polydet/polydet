#!/usr/bin/env python3

import argparse
import sys
import json

from polydet import magic, scan, rules, PolyglotLevel


class PolyglotLevelEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, PolyglotLevel):
            return {
                'isValid': o.is_valid,
                'suspiciousChunks': o.suspicious_chunks,
                'embedded': sorted(o.embedded)
            }

        return super().default(o)


def display_results(results: {str: {str: PolyglotLevel}}, fp):
    json.dump(results, fp, cls=PolyglotLevelEncoder)


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
    arg_parser.add_argument('-o', '--output', default='-', help='Output file')
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

    results = dict()
    for filename in args.files:
        results[filename] = scan(filename, use_magic=args.magic)

    if args.output != '-':
        with open(args.output) as output:
            display_results(results, output)
    else:
        display_results(results, sys.stdout)


if __name__ == '__main__':
    main()
