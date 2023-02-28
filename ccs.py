#!/usr/bin/env python3
# Copyright (c) 2022 Chris Anley All Rights Reserved
import regex
import sys
import signal
import os

# Code Credential Scanner


SKIP_EXTS = [
    regex.compile(r'\.DS_Store$'),
    regex.compile(r'\.css$'),
    regex.compile(r'\.deps\.json$'),
    regex.compile(r'\.dll$'),
    regex.compile(r'\.eot$'),
    regex.compile(r'\.exe$'),
    regex.compile(r'\.gif$'),
    regex.compile(r'\.ico$'),
    regex.compile(r'\.jar$'),
    regex.compile(r'\.jpg$'),
    regex.compile(r'\.min\.js$'),
    regex.compile(r'\.mov$'),
    regex.compile(r'\.mp4$'),
    regex.compile(r'\.png$'),
    regex.compile(r'\.svg$'),
    regex.compile(r'\.tif$'),
    regex.compile(r'\.tiff$'),
    regex.compile(r'\.ttf$'),
    regex.compile(r'\.woff$'),
    regex.compile(r'\.zip$'),
    regex.compile(r'salt\.7$'),
]

SKIP_DIRS = [
    regex.compile('/External/'),
    regex.compile('/Samples/'),
    regex.compile('/NuGet/'),
    # regex.compile('/Setup/'),
    regex.compile('/i18n/'),
    regex.compile('/li8n/'),
    regex.compile('/node_modules/'),
    regex.compile('/packages/'),
    regex.compile('(?i)/test/'),
    regex.compile('/third_party/'),
    regex.compile('/vendor/'),
    regex.compile(r'/\.svn/'),
    regex.compile(r'/\.git/'),
    regex.compile('example'),
]

SHORT_BAD_PASSWORDS = [  # All taken from Daniel Miessler's bad password lists
    # at https://github.com/danielmiessler/SecLists/tree/master/Passwords
    # Short strings are very likely to be non-passwords, but we allow these specific strings
    # since they are known-bad, common passwords
    '111111',
    '123',
    '123123',
    '1234',
    '12345',
    '123456',
    '123654',
    '159753',
    '1q2w3e',
    'a12345',
    'abc123',
    'admin',
    'asd123',
    'asdf',
    'azerty',
    'bogus',
    'dev',
    'devop',
    'devops',
    'docker',
    'dragon',
    'love',
    'mesh',
    'monkey',
    'mysql',
    'pass',
    'prod',
    'qazwsx',
    'qwerty',
    'root',
    'secret',
    'shadow',
    'swarm',
    'stage',
    'tinkle',
    'test',
    'toor',
    'xxxx',
]

PWD = r'''[^;<$\n\s'"]'''
NON_PWD = r'''[;<$\n\s'"]'''
GUID_LOWER = r'''[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'''
CLIENT_SECRET = r'''[a-zA-Z0-9_~\-\%/\+\=]{22,300}'''

# Regexes we use to extract likely passwords
# if password is quoted, capture with quote-nonquote-quote
# otherwise, catpure with (nonquote) nonpassword terminator char

pwd_rules = [
    (regex.compile(r'(.*)(AKIA[A-Z0-9]{16})([^A-Z0-9].*)'), 1, 20, None),  # AWS Access Key
    (regex.compile(r'(.*\W)(xox[abpr]-' + PWD + '{20,})(' + NON_PWD + '.*)'), 2, 20, None),  # Slack access token
    (regex.compile(r'(.*)(\$\da?\$\w{1,99}\$' + PWD + r'*)(' + NON_PWD + r'.*)'), 3, 20, None),  # password hash $2a$10$...
    (regex.compile(r'(.*://\w+:)([^@]*)(@.*)'), 4, 20, None),  # xyz://user:pass@
    (regex.compile(r'("\w+@(?:\w+\.)+\w+:)([^"/]+)(")'), 5, 20, None),  # "x@y.com:pass"
    (regex.compile(r'((?i).*<ApiKey[^>]*>)(' + PWD + '+)(' + NON_PWD + '.*)'), 6, 20, None),
    (regex.compile(r'((?i).*ApiKey\s*[=:]\s*")([^"]*)(".*)'), 7, 20, None),
    (regex.compile(r'((?i).*ApiKey"[^"]+")([^"]*)(".*)'), 8, 20, None),
    (regex.compile(r'((?i).*<ApiSecret[^>]*>)(' + PWD + '*)(' + NON_PWD + '.*)'), 9, 20, None),
    (regex.compile(r'((?i).*AccountKey\s*[=:])(' + PWD + '*)(' + NON_PWD + '.*)'), 10, 20, None),
    (regex.compile(r'(.*Authorization: (?:Basic|Bearer)\s+)(' + PWD + '*)(' + NON_PWD + '.*)'), 11, 20, None),
    (regex.compile(r'((?i).*NetworkCredential\s*\(\s*"[^"]*"\s*,\s*")([^"]*)(".*)'), 12, 20, None),
    (regex.compile(r'((?i).*_pass\s*[\!\=]?\=\s*")([^"\n]+)("[^\n]*)'), 13, 20, None),  # _pass != / == "foo"
    (regex.compile(r'''((?i).*_passwd\s*[=:]\s*["'])([^"'\n]+)(["'][^\n]*)'''), 14, 20, None),
    (regex.compile(r'((?i).*auth_token\s*[=:]\s*)(' + PWD + '*)(' + NON_PWD + '.*)'), 15, 20, None),
    (regex.compile(r'((?i).*password\s*[=:]\s*)(' + PWD + '*)(' + NON_PWD + '.*)'), 16, 20, regex.compile(r'(?i)\.ya?ml')),  # xxxpassword : asdf
    (regex.compile(r'''((?i).*password\s*[=:]\s*["'])([^"'\n]+)(["'][^\n]*)'''), 17, 20, None),  # xxxpassword : 'asdf'
    (regex.compile(r'''((?i).*password\s*[\!\=]\=\s*['"])([^'"\n]+)(['"][^\n]*)'''), 18, 20, None),  # password != / == "foo"
    (regex.compile(r'''((?i).*"password\w*"[:\=\s]+")([^"\n]+)("[^\n]*)'''), 19, 20, None),  # "passwordxxx": "foo
    (regex.compile(r'''((?i)\$password\w*\s*=*\s')([^']+)('.*)'''), 20, 20, None),
    (regex.compile(r'''((?i)\$\w*password\s*=\s*')([^']+)('.*)'''), 21, 20, None),
    (regex.compile(r'''((?i)"\w*ClientId":\s*")(''' + GUID_LOWER + r''')(".*)'''), 22, 20, None),
    (regex.compile(r'''((?i)"\w*TenantId":\s*")(''' + GUID_LOWER + r''')(".*)'''), 23, 20, None),
    (regex.compile(r'''((?i)"\w*ClientSecret":\s*")(''' + CLIENT_SECRET + r''')(".*)'''), 24, 20, None),
    (regex.compile(r'''((?i)"\w*EncryptionKey":\s*")(''' + CLIENT_SECRET + r''')(".*)'''), 25, 20, None),
    (regex.compile(r'''((?i).*(?:api|access|auth|client|secret)_key\s*:\s*)([^"\n]+)("[^\n]*)'''), 26, 20, None),  # _key: foo
    (regex.compile(r'''((?i).*(?:api|access|auth|client|secret)_key\s*[\!\=]?\=\s*")([^"\n]+)("[^\n]*)'''), 27, 20, None),  # _key = / != / == "foo"
    (regex.compile(r'((?i).*(?:api|access|auth|client|secret)_key\s*[\!\=]?\=\s*)(' + PWD + '+)(' + NON_PWD + '*)'), 28, 20, None),  # _key = / != / == foo
    (regex.compile(r'''((?i).*(?:api|access|auth|client|secret)_key"\s*:\s*")([^"\n]+)("[^\n]*)'''), 29, 20, None),  # _key": "foo"
    (regex.compile(r'''((?i).*key\s*=\s*.*GetBytes\(")([^"\n]+)("[^\n]*)'''), 30, 20, None),
    (regex.compile(r'''((?i).*key\s*=\s*"\w*password\w*"\s+value\s*=\s*")([^"\n]{0,200})("[^\n]{0,200})'''), 31, 20, None),
    (regex.compile(r'''((?i).*key\s*=\s*"\w+pwd"\s+value\s*=\s*")([^"\n]{0,200})("[^\n]{0,200})'''), 32, 20, None),
    (regex.compile(r'''((?i).*key\s*=\s*"\w+secret"\s+value\s*=\s*")([^"\n]{0,200})("[^\n]{0,200})'''), 33, 20, None),
    (regex.compile(r'''((?i).*pwd\s*[=:]\s*)([^;'"<$\n\s]*)[;'"<$\n\s](.*)'''), 34, 20, None),
    (regex.compile(r'''((?i).*AzureStorageKey.*AccountKey\s*=\s*)([^;'"<$\n\s\\]*)([;'"<$\n\s\\].*)'''), 35, 20, None),
    (regex.compile(r'''((?i).*secret\s*[=:]\s*)([^;'"<$\n\s]*)[;'"<$\n\s](.*)'''), 36, 20, None),
    (regex.compile(r'''(curl.{0,200}\s-u\s*)([^\s]+)(\s.*)'''), 37, 20, None),
    (regex.compile(r'''(mysql.{0,200}\s-p\s*)([^\s]+)(\s.*)'''), 38, 20, None),
    (regex.compile(r'''("AUTH"[,\s]+")([^\n]{5,99})("[^\n]{0,200})'''), 39, 20, None),
    (regex.compile(r'((?i)\w*secret\s*=\s*")(' + CLIENT_SECRET + r')(".*)'), 40, 20, None),
    (regex.compile(r'''((?i).*api_token\s*,\s*')(''' + PWD + r'''*)('\s*''' + NON_PWD + '.*)'), 41, 20, None),
    (regex.compile(r'''((?i)\w*API_KEY\s*=\s*")(''' + CLIENT_SECRET + r''')(".*)'''), 42, 20, None),
    (regex.compile(r'''((?i)\w*AUTH_KEY\s*=\s*")(''' + CLIENT_SECRET + r''')(".*)'''), 43, 20, None),
    (regex.compile(r'''((?i)\w*ACCESS_KEY\s*=\s*")(''' + CLIENT_SECRET + r''')(".*)'''), 44, 20, None),
]

# Regexes we use to exclude likely false-positive passwords
# Many of these are artefacts introduced by the typical context of the password detection regexes,
# such as filenames, html/dom fragments, and other common string constants.
non_password_regexes = [
    regex.compile(r'''#[0-9a-f]{6}'''),  # web colour code
    regex.compile(r'''(\%d|\%n|\%s|\%y|\%d|\%m|\%v)'''),  # c format specifiers
    regex.compile(r'''(\\n|\\t|\\r)'''),  # escape codes
    regex.compile(r'''(://)'''),  # url
    regex.compile(r''':[^:]*:'''),  # :something:
    regex.compile(r'''</?\w+>'''),  # xml or html tag
    regex.compile(r'''[,\.]\s'''),  # comma space or dot space
    regex.compile(r'''[\$\@]\(\w+\)'''),  # interpolation
    regex.compile(r'''[\)\}\],\(\[\{]$'''),
    regex.compile(r'''\$\('''),
    regex.compile(r'''\$php'''),
    regex.compile(r'''\):?$'''),  # ends in ')' or '):'
    regex.compile(r'''\*\.'''),
    regex.compile(r'''\.(dll|exe|so|doc|pdf|hml|css|js|gif|png|jpg|jpeg|sh)'''),
    regex.compile(r'''\.[^\.]*\.'''),  # version number
    regex.compile(r'''\[^\\]*\\'''),  # windows path
    regex.compile(r'''\\[ux][0-9a-f]{2}'''),  # unicode or hex char
    regex.compile(r'''(^\s|\s[^\s]*\s|\s\|\s|\s{4})'''),  # spaces; probably text
    regex.compile(r'''\{#?[a-z0-9_ ]+#?\}'''),  # interpolation
    regex.compile(r'''^(0|\\)[xX][0-9a-f]{4,}$'''),  # hex constant
    regex.compile(r'''^(A+|X+|Z+|a+|x+|z+)$'''),  # AAAAAAA XXXXXXX etc
    regex.compile(r'''^--'''),  # command line option flag
    regex.compile(r'''^@\w+$'''),
    regex.compile(r'''^[0-9:./ ]$'''),  # date/time or version number
    regex.compile(r'''^[^a-z]+$'''),  # entirely non alpha
    regex.compile(r'''^\$\w+$'''),
    regex.compile(r'''(^false$|^sha1-|^sha256-|^sha512-|^split$|^string\.|^this\.|^true$|^user\.|^xml|^xsi)'''),
    regex.compile(r'''_[^_]*_'''),
    regex.compile(r'''^(any|await|hash|new|nil|none|null|&gt)$'''),  # entire password is x
    regex.compile(r'''(border|click|focus|scroll|keydown|keyup|margin|_pass|passwd|password|pwd|resize|width|height|value)$'''),  # ends with
    regex.compile(r'''(api.*key|bearer|cdata|client|config|credentials|data\s*-|digest|either|enter\s|error|example|function)'''),
    regex.compile(r'''(general|\.get|href|html|http|image|index|json|lambda|length|md5|mm:ss)'''),
    regex.compile(r'''(passphrase|\Wpassword\W|placeholder|plaintext|redacted|secret|settings|string|text/|tlsv|token|type|uint|utf-8|video|xml|yyyy)'''),
]


def get_passwords_from_line(fname, line):
    results = []

    for pwd_regex, rule_id, score, files_include in pwd_rules:
        if files_include:
            if not files_include.search(fname):
                continue  # this rule doesn't apply to this file
        remaining = line
        prefix = ''
        while remaining and remaining != '':
            result = pwd_regex.search(remaining)

            if not result:
                break

            groups = result.groups()  # noqa
            g1 = groups[0] if len(groups) > 0 else ''
            g2 = groups[1] if len(groups) > 1 else ''
            g3 = groups[2] if len(groups) > 2 else ''
            results = results + [(rule_id, prefix + g1, g2, g3, score)]
            remaining = g3
            prefix = g1 + g2
            if len(prefix) > 200: prefix = prefix[-200:]  # noqa
    return results


def is_not_a_password(pwd):
    # pwd is interpolation string, web rgb code, unicode char etc
    for npregex in non_password_regexes:
        if npregex.search(pwd.lower()):
            return True
    return False


def has_non_ascii(s):
    for ch in s:  # if pwd has non-ascii chars, ignore the password
        if ord(ch) > 127:
            return True
    return False


def is_file_suppression_comment(text):
    # flake8: noqa
    suppression_comment_indicators = [
        'flake8: noqa',
        '# noqa file',
    ]
    for indicator in suppression_comment_indicators:
        if indicator in text:
            return True
    return False


def is_line_suppression_comment(text):
    suppression_comment_indicators = [
        '# noinspection',
        '# noqa',
        '#noqa',
        '@SuppressWarnings',
        'DevSkim',
        'NOLINT',
        'NOSONAR',
        'checkmarx',
        'coverity',
        'fortify',
        'noinspection',
        'nosec',
        'safesql',
        'veracode',
    ]
    for indicator in suppression_comment_indicators:
        if indicator in text:
            return True
    return False


def check_line_password(fname, text):
    try:
        # check if this line contains a password, return text if yes, plus score?
        outputs = []

        # if line has an 'ignore' comment, or is ridiculously long, ignore this line
        if not nosuppress:
            if is_line_suppression_comment(text): return outputs  # noqa
        if len(text) > 8192: return outputs  # noqa

        results = get_passwords_from_line(fname, text)

        for rule_id, prefix, pwd, suffix, starting_score in results:
            # check conditions under which we stop scoring the candidate password
            # allow very short passwords only if they're very common and bad (taken from the top1000 password list)
            if len(pwd) < 5: continue  # noqa
            if len(pwd) > 200: continue  # noqa
            if 'publickeytoken' in prefix.lower(): continue  # noqa
            if 'example' in prefix.lower() or 'example' in suffix.lower(): continue  # noqa
            # if has_non_ascii(pwd): continue  # noqa
            if is_not_a_password(pwd) and not pwd in SHORT_BAD_PASSWORDS: continue  # noqa # ignore known non-password patterns
            outputs = outputs + [(rule_id, prefix + ':' + pwd + ':' + suffix, starting_score)]

        return outputs

    except Exception as e:
        eprint("Exception: " + str(e))
        eprint("")


def skip_file(fname):
    global ns
    if ns:
        return False
    for skip in SKIP_DIRS:
        if skip.search(fname):
            return True
    for skip in SKIP_EXTS:
        if skip.search(fname):
            return True
    return False


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def write_result(result_msg):
    while result_msg.endswith('\n'):
        result_msg = result_msg[0:-1]
    print(result_msg)


def do_line_cred_check(fname, line, line_num):
    try:
        fmt = '{fname}:{line_num}:{g0}'
        results = check_line_password(fname, line)
        for rule_id, result, score in results:  # noqa
            score_str = '%02d' % score
            g0 = 'Rule:' + str(rule_id) + ':' + result
            msg = fmt.format(fname=fname, line_num=line_num, score_str=score_str, g0=g0)
            write_result(msg)  # noqa

    except Exception as e:
        eprint("Exception: " + str(e))
        eprint("")


def do_checks():
    if a:
        mode = 'rb'
    else:
        mode = 'r'

    for root, subdirs, files in os.walk(os.path.abspath(".")):
        for fn in files:
            fname = str(root) + "/" + str(fn)
            # exclude some files/paths based on verbosity options
            if skip_file(fname):
                continue
            if print_progress:
                eprint('Scanning ' + fname)

            try:
                with open(fname, mode) as f:
                    line_num = 1
                    for line in f:
                        if a: line = str(line)  # noqa
                        if not nosuppress:
                            if is_file_suppression_comment(line): break  # noqa
                        do_line_cred_check(fname, line, line_num)
                        line_num += 1
            except:  # noqa
                continue


def syntax():
    eprint(
        '''code-cred-scan.py : Code Credential Scanning Tool [ by Chris Anley ]
        Syntax: 
        Run from code root directory. Output is to stdout, errors and 'verbose' messages are to stderr.
        code-cred-scan.py [options]
        -a   : check all files, including binaries (i.e. files containing invalid utf-8 chars)
        -p   : print progress
        -v   : quite verbose
        -vv  : annoyingly verbose
        -vvv : pointlessly verbose
        -ns  : no skip : don't skip files/directories that are irrelevant, like test, /vendor/, /node_modules/, .zip etc
        -sa  : scan all files, not just recommended / code files
        -nosuppress : ignore suppression comments such as # noqa, at line and file level 
        ''')


a = False
v = False
vv = False
vvv = False
ns = False
sa = False
sc = False
print_progress = False
nosuppress = False


def do_main():
    global a, v, vv, vvv, ns, sa, sc, print_progress, nosuppress
    argc = len(sys.argv)
    argv = sys.argv

    for i in range(1, argc):
        if argv[i] in ['-h', '-?', '--help', '--h', '/?']:
            return syntax()

        if argv[i] == '-a':
            a = True
            ns = True  # no skip directories
            sa = True  # apply all checks to all files
            continue
        if argv[i] == '-v':
            v = True
            continue
        if argv[i] == '-vv':
            v = True
            vv = True
            continue
        if argv[i] == '-vvv':
            v = True
            vv = True
            vvv = True
            print_progress = True
            continue
        if argv[i] == '-ns':  # no skip directories / files
            ns = True
            continue
        if argv[i] == '-sa':  # apply all checks to all files
            sa = True
            continue
        if argv[i] == '-p':
            print_progress = True
        if argv[i] == '-nosuppress':
            nosuppress = True

    do_checks()


def signal_handler(sig, frame):  # noqa
    os._exit(0)  # noqa


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    do_main()

