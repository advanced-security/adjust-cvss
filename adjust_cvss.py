import argparse
import json
import re
from globber import match


def parse_pattern(line):
    sepchar = ':'
    escchar = '\\'
    rule_pattern = ''
    score_pattern = ''
    seen_separator = False

    i = 0
    while i < len(line):
        c = line[i]
        i = i + 1
        if c == sepchar:
            if seen_separator:
                raise Exception('Invalid pattern: "' + line + '" Contains more than one separator!')
            seen_separator = True
            continue
        elif c == escchar:
            nextc = line[i] if (i < len(line)) else None
            if nextc in ['+' , '-', escchar, sepchar]:
                i = i + 1
                c = nextc
        if seen_separator:
            score_pattern = score_pattern + c
        else:
            rule_pattern = rule_pattern + c

    return rule_pattern, str(float(score_pattern))


def adjust_cvss(args):
    if args.split_lines:
        tmp = []
        for p in args.patterns:
            tmp = tmp + re.split('\r?\n', p)
        args.patterns = tmp

    args.patterns = [parse_pattern(p) for p in args.patterns if p]

    print('Given patterns:')
    for input_id_pattern, input_score_pattern in args.patterns:
        print(
            'IDs: {id_pattern}    scores: {score_pattern}'.format(
                id_pattern=input_id_pattern,
                score_pattern=input_score_pattern
            )
        )

    with open(args.input, 'r', encoding="utf-8") as f:
        s = json.load(f)

    for run in s.get('runs', []):
        # tool --> extensions --> rules match
        for extension in run.get('tool', {}).get('extensions', []):
            for rule in extension.get('rules', []):
                props = rule.get('properties', [])

                rule_id = props.get('id', '')
                cvss = props.get('security-severity', None)

                if cvss:
                    for input_id_pattern, input_score_pattern in args.patterns:
                        if match(input_id_pattern, rule_id):
                            print('adjusted')
                            props['security-severity'] = input_score_pattern

        # tool --> driver --> rules match
        for rule in run.get('tool', {})['driver'].get('rules', []):
            props = rule.get('properties', [])
            rule_id = rule.get('id', [])
            
            cvss = props.get('security-severity', None)

            if cvss:
                for input_id_pattern, input_score_pattern in args.patterns:
                    if match(input_id_pattern, rule_id):
                        print('adjusted')
                        props['security-severity'] = input_score_pattern

    with open(args.output, 'w', encoding="utf-8") as f:
        json.dump(s, f, indent=2)


def main():
    parser = argparse.ArgumentParser(
        prog='adjust-cvss'
    )
    parser.add_argument(
        '--input',
        help='Input SARIF file',
        required=True
    )
    parser.add_argument(
        '--output',
        help='Output SARIF file',
        required=True
    )
    parser.add_argument(
        '--split-lines',
        default=False,
        action='store_true',
        help='Split given patterns on newlines.'
    )
    parser.add_argument(
        'patterns',
        help='score patterns.',
        nargs='+'
    )

    def print_usage(args):
        print(parser.format_usage())

    args = parser.parse_args()
    adjust_cvss(args)


main()
