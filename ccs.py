#!/usr/bin/env python3
# Copyright (c) 2022 Chris Anley All Rights Reserved
import os
import re
import signal
import sys

# Code Credential Scanner
wrote_result = False

SKIP_EXTS = [
    re.compile(r'\.DS_Store$'),
    re.compile(r'\.css$'),
    re.compile(r'\.deps\.json$'),
    re.compile(r'\.dll$'),
    re.compile(r'\.eot$'),
    re.compile(r'\.exe$'),
    re.compile(r'\.gif$'),
    re.compile(r'\.ico$'),
    re.compile(r'\.jar$'),
    re.compile(r'\.jpg$'),
    re.compile(r'\.min\.js$'),
    re.compile(r'\.mov$'),
    re.compile(r'\.mp4$'),
    re.compile(r'\.png$'),
    re.compile(r'\.svg$'),
    re.compile(r'\.tif$'),
    re.compile(r'\.tiff$'),
    re.compile(r'\.ttf$'),
    re.compile(r'\.woff$'),
    re.compile(r'\.zip$'),
    re.compile(r'salt\.7$'),
]

SKIP_DIRS = [
    re.compile('/External/'),
    re.compile('/Samples/'),
    re.compile('/NuGet/'),
    # re.compile('/Setup/'),
    re.compile('/i18n/'),
    re.compile('/li8n/'),
    re.compile('/node_modules/'),
    re.compile('/packages/'),
    re.compile('(?i)/test/'),
    re.compile('/third_party/'),
    re.compile('/vendor/'),
    re.compile(r'/\.svn/'),
    re.compile(r'/\.git/'),
    re.compile('example'),
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
EMAIL_ADDR = r'''[.\-_a-zA-Z0-9]{1,80}\@(?:[a-z0-9][a-z0-9-]{1,80}\.){1,}[a-z]{1,10}'''

# Regexes we use to extract likely passwords

pwd_rules = [
    # PASSWORD rules are reported first, in case we only report one result for the line
    (re.compile(r'(.*\W)(xox[abpr]-' + PWD + '{20,})(' + NON_PWD + '[^\n]*)'), 2, 'PASSWORD', None),  # Slack access token
    (re.compile(r'(.*)(\$\da?\$\w{1,99}\$' + PWD + r'*)(' + NON_PWD + r'[^\n]*)'), 3, 'PASSWORD', None),  # password hash
    (re.compile(r'(.*://[^:\n]+:)([^@:\n/]+)(@[^\n]*)'), 4, 'PASSWORD', None),  # xyz://user:pass@
    (re.compile(r'("\w+@(?:\w+\.)+\w+:)([^"/]+)(")'), 5, 'PASSWORD', None),  # "x@y.com:pass"
    (re.compile(r'(?i)(.*<ApiKey[^>]*>)(' + PWD + '+)(' + NON_PWD + '.*)'), 6, 'PASSWORD', None),
    (re.compile(r'(?i)(.*ApiKey\s*[=:]\s*")([^"]*)("[^\n]*)'), 7, 'PASSWORD', None),
    (re.compile(r'(?i)(.*ApiKey"[^"]+")([^"]*)("[^\n]*)'), 8, 'PASSWORD', None),
    (re.compile(r'(?i)(.*<ApiSecret[^>]*>)(' + PWD + '*)(' + NON_PWD + '[^\n]*)'), 9, 'PASSWORD', None),
    (re.compile(r'(?i)(.*AccountKey\s*[=:])(' + PWD + '*)(' + NON_PWD + '[^\n]*)'), 10, 'PASSWORD', None),
    (re.compile(r'(.*Authorization: (?:Basic|Bearer)\s+)(' + PWD + '*)(' + NON_PWD + '[^\n]*)'), 11, 'PASSWORD', None),
    (re.compile(r'(?i)(.*NetworkCredential\s*\(\s*"[^"]*"\s*,\s*")([^"]*)("[^\n]*)'), 12, 'PASSWORD', None),
    (re.compile(r'(?i)(.*_pass\s*[!=]?=\s*")([^"\n]+)("[^\n]*)'), 13, 'PASSWORD', None),  # _pass != / == "foo"
    (re.compile(r'''(?i)(.*_passwd\s*[=:]\s*["'])([^"'\n]+)(["'][^\n]*)'''), 14, 'PASSWORD', None),
    (re.compile(r'(?i)(.*auth_token\s*[=:]\s*)(' + PWD + '*)(' + NON_PWD + '[^\n]*)'), 15, 'PASSWORD', None),
    (re.compile(r'(?i)(.*password\s*[=:]\s*)(' + PWD + '*)(' + NON_PWD + '[^\n]*)'), 16, 'PASSWORD', re.compile(r'(?i)\.ya?ml')),  # xxxpassword : asdf
    (re.compile(r'''(?i)(.*password\s*[=:]\s*["'])([^"'\n]+)(["'][^\n]*)'''), 17, 'PASSWORD', None),  # xxxpassword : 'asdf'
    (re.compile(r'''(?i)(.*password\s*[!=]=\s*['"])([^'"\n]+)(['"][^\n]*)'''), 18, 'PASSWORD', None),  # password != / == "foo"
    (re.compile(r'''(?i)(.*"password\w*"[:=\s]+")([^"\n]+)("[^\n]*)'''), 19, 'PASSWORD', None),  # "passwordxxx": "foo
    (re.compile(r'''(?i)(\$password\w*\s*=*\s')([^']+)('[^\n]*)'''), 20, 'PASSWORD', None),
    (re.compile(r'''(?i)(\$\w*password\s*=\s*')([^']+)('[^\n]*)'''), 21, 'PASSWORD', None),
    (re.compile(r'''(?i)("\w*ClientSecret":\s*")(''' + CLIENT_SECRET + r''')("[^\n]*)'''), 24, 'PASSWORD', None),
    (re.compile(r'''(?i)("\w*EncryptionKey":\s*")(''' + CLIENT_SECRET + r''')("[^\n]*)'''), 25, 'PASSWORD', None),
    (re.compile(r'''(?i)(.*(?:api|access|auth|client|secret)_key\s*:\s*)([^"\n]+)("[^\n]*)'''), 26, 'PASSWORD', None),  # _key: foo
    (re.compile(r'''(?i)(.*(?:api|access|auth|client|secret)_key\s*[!=]?=\s*")([^"\n]+)("[^\n]*)'''), 27, 'PASSWORD', None),  # _key = / != / == "foo"
    (re.compile(r'(?i)(.*(?:api|access|auth|client|secret)_key\s*[!=]?=\s*)(' + PWD + '{18,200})(' + NON_PWD + '*)'), 28, 'PASSWORD', None),  # _key = / != / == foo
    (re.compile(r'''(?i)(.*(?:api|access|auth|client|secret)_key"\s*:\s*")([^"\n]+)("[^\n]*)'''), 29, 'PASSWORD', None),  # _key": "foo"
    (re.compile(r'''(?i)(.*key\s*=\s*.*GetBytes\(")([^"\n]+)("[^\n]*)'''), 30, 'PASSWORD', None),
    (re.compile(r'''(?i)(.*key\s*=\s*"\w*password\w*"\s+value\s*=\s*")([^"\n]{0,200})("[^\n]{0,200})'''), 31, 'PASSWORD', None),
    (re.compile(r'''(?i)(.*key\s*=\s*"\w+pwd"\s+value\s*=\s*")([^"\n]{0,200})("[^\n]{0,200})'''), 32, 'PASSWORD', None),
    (re.compile(r'''(?i)(.*key\s*=\s*"\w+secret"\s+value\s*=\s*")([^"\n]{0,200})("[^\n]{0,200})'''), 33, 'PASSWORD', None),
    (re.compile(r'''(?i)(.*pwd\s*[=:]\s*)([^;'"<$\n\s]*)[;'"<$\n\s]([^\n]*)'''), 34, 'PASSWORD', None),
    (re.compile(r'''(?i)(.*AzureStorageKey.*AccountKey\s*=\s*)([^;'"<$\n\s\\]*)([;'"<$\n\s\\][^\n]*)'''), 35, 'PASSWORD', None),
    (re.compile(r'''(?i)(.*secret\s*[=:]\s*)([^;'"<$\n\s]*)[;'"<$\n\s](.*)'''), 36, 'PASSWORD', None),
    (re.compile(r'''(curl.{0,200}\s-u\s*)([^\s]+)(\s.*)'''), 37, 'PASSWORD', None),
    (re.compile(r'''(mysql.{0,200}\s-p\s*)([^\s]+)(\s.*)'''), 38, 'PASSWORD', None),
    (re.compile(r'''("AUTH"[,\s]+")([^\n]{5,99})("[^\n]{0,200})'''), 39, 'PASSWORD', None),
    (re.compile(r'(?i)(\w*secret\s*=\s*")(' + CLIENT_SECRET + r')("[^\n]*)'), 40, 'PASSWORD', None),
    (re.compile(r'''(?i)(.*api_token\s*,\s*')(''' + PWD + r'''*)('\s*''' + NON_PWD + '[^\n]*)'), 41, 'PASSWORD', None),
    (re.compile(r'''(?i)(\w*API_KEY\s*=\s*")(''' + CLIENT_SECRET + r''')("[^\n]*)'''), 42, 'PASSWORD', None),
    (re.compile(r'''(?i)(\w*AUTH_KEY\s*=\s*")(''' + CLIENT_SECRET + r''')("[^\n]*)'''), 43, 'PASSWORD', None),
    (re.compile(r'''(?i)(\w*ACCESS_KEY\s*=\s*")(''' + CLIENT_SECRET + r''')("[^\n]*)'''), 44, 'PASSWORD', None),
    (re.compile(r'''(?i)(\w*TOKEN\s*=\s*['"])(''' + CLIENT_SECRET + r''')(['"][^\n]*)'''), 45, 'PASSWORD', None),
    (re.compile(r'''(?i)(\w*_PASS\s*=\s*")(''' + CLIENT_SECRET + r''')("[^\n]*)'''), 46, 'PASSWORD', None),
    (re.compile(r'''(?i)("auth"\s*:\s*")(''' + CLIENT_SECRET + r''')("[^\n]*)'''), 47, 'PASSWORD', None),
    (re.compile(r'''(?i)(password\s+")(\w{5,200})("[^\n]*)'''), 48, 'PASSWORD', None),
    (re.compile(r'''(?i)("pass"\s*:\s*")(''' + PWD + r'''{5,100})("[^\n]*)'''), 49, 'PASSWORD', None),
    (re.compile(r'''(?i)("passphrase"\s*:\s*")(''' + PWD + r'''{5,100})("[^\n]*)'''), 50, 'PASSWORD', None),
    (re.compile(r'''(?i)(machine\s+[^\s]+\s+login\s+[^\s]+\s+password\s+)([^\s]+)(\s+[^\n]*)'''), 51, 'PASSWORD', None),
    (re.compile(r'''(?i)(_auth\s*=\s*)([^\s]{5,200})([^\n]*)'''), 52, 'PASSWORD', None),
    (re.compile(r'''(?i)(SECRET_KEY\s*=\s*)([^\s]{5,200})([^\n]*)'''), 53, 'PASSWORD', None),
    (re.compile(r'''(?i)(\.login\('[^'\n]+',\s*')([^\s\n']{5,200})([^\n]*)'''), 54, 'PASSWORD', None),
    (re.compile(r'''(?i)(secret_key_base:\s*)([^\s\n]{5,200})([^\n]*)'''), 55, 'PASSWORD', None),
    (re.compile(r'''(?i)(APP_KEY\s*=\s*)([^\s\n]{5,200})([^\n]*)'''), 56, 'PASSWORD', None),
    (re.compile(r'''(?i)(\w*_PASSWORD\s*=\s*)([^\s\n]{5,200})([^\n]*)'''), 57, 'PASSWORD', None),
    (re.compile(r'''(.*)(\$apr1\$\w{1,99}\$[^;<$\n\s'"]*)([^\n]*)'''), 58, 'PASSWORD', None),  # password hash $apr$salt$...
    (re.compile(r'''(?i)(\$\w*passwd\s*=\s*')([^\s\n']{5,200})([^\n]*)'''), 59, 'PASSWORD', None),
    (re.compile(r'''(?i)(\w*_PASSWORD',\s*')([^\s\n']{5,200})([^\n]*)'''), 60, 'PASSWORD', None),
    (re.compile(r'''(?i)(\w*_KEY',\s*')([^\s\n']{5,200})([^\n]*)'''), 61, 'PASSWORD', None),
    (re.compile(r'''(?i)("encryptedPassword":\s*")([^\s\n"]{5,200})([^\n]*)'''), 62, 'PASSWORD', None),
    (re.compile(r'''(?i)(api_key:\s*)([^\s\n"]{5,200})([^\n]*)'''), 63, 'PASSWORD', None),
    (re.compile(r'''(.*)(\$2y\$\d+\$[^\s\n"']{5,200})([^\n]*)'''), 64, 'PASSWORD', None),
    (re.compile(r'''(?i)(\w*Password"\s*:\s*")([^\s\n"]{5,200})([^\n]*)'''), 65, 'PASSWORD', None),
    (re.compile(r'''(?i)(\w*Passphrase"\s*:\s*")([^\s\n"]{5,200})([^\n]*)'''), 66, 'PASSWORD', None),
    (re.compile(r'''(.*)(\$\d\$[^$]{1,40}\$[^\s\n"']{5,200})([^\n]*)'''), 67, 'PASSWORD', None),
    (re.compile(r'''(?i)(.*<Pass>)([^<\n]{5,200})(</Pass>[^\n]*)'''), 68, 'PASSWORD', None),
    (re.compile(r'''(?i)(.*<Pass\s+[^>]+>)([^<\n]{5,200})(</Pass>[^\n]*)'''), 69, 'PASSWORD', None),
    (re.compile(r'''(?i)(.*\w*API_KEY\s*=\s*['"]?)([^\n\s'"]{5,200})([^\n]*)'''), 81, 'PASSWORD', None),
    (re.compile(r'''(?i)(.*MLAB_PASS\s*=\s*)([^\n\s]{5,200})([^\n]*)'''), 82, 'PASSWORD', None),

    # USER rules below here
    (re.compile(r'''(?i)("\w*ClientId":\s*")(''' + GUID_LOWER + r''')("[^\n]*)'''), 22, 'USER', None),
    (re.compile(r'''(?i)("\w*TenantId":\s*")(''' + GUID_LOWER + r''')("[^\n]*)'''), 23, 'USER', None),
    (re.compile(r'''(?i)(.*ACCESS_KEY_ID\s*=\s*)([^\n\s]{18,200})([^\n]*)'''), 70, 'USER', None),
    (re.compile(r'''(?i)(.*S3_BUCKET\s*=\s*)([^\n\s]{5,200})([^\n]*)'''), 71, 'USER', None),
    (re.compile(r'''(?i)(.*RDS_HOST\s*=\s*)([^\n\s]{5,200})([^\n]*)'''), 72, 'USER', None),
    (re.compile(r'''(?i)(.*MLAB_URL\s*=\s*)([^\n\s]{5,200})([^\n]*)'''), 73, 'USER', None),
    (re.compile(r'''(?i)(.*MLAB_DB\s*=\s*)([^\n\s]{5,200})([^\n]*)'''), 74, 'USER', None),
    (re.compile(r'''(?i)(.*_USERNAME\s*=\s*["'])([^\n\s"']{5,200})([^\n]*)'''), 75, 'USER', None),
    (re.compile(r'''(?i)(.*_EMAIL\s*=\s*["'])([^\n\s"']{5,200})([^\n]*)'''), 76, 'USER', None),
    (re.compile(r'''(?i)(.*hostname\s+)([^\n\s"'.]+\.[^\n\s"'.]+\.[^\n\s"']+)([^\n]*)'''), 77, 'USER', None),
    (re.compile(r'''(?i)(.*username\s+)([^\n\s]{5,200})([^\n]*)'''), 78, 'USER', None),
    (re.compile(r'''(?i)(.*"host"\s*:\s*)([^\n\s]{5,200})([^\n]*)'''), 79, 'USER', None),
    (re.compile(r'''(?i)(.*"user"\s*:\s*)([^\n\s]{5,200})([^\n]*)'''), 80, 'USER', None),
    (re.compile(r'''(?i)(.*MAILCHIMP_LIST_ID\s*=\s*['"])([^\n\s'"]{5,200})([^\n]*)'''), 83, 'USER', None),
    (re.compile(r'''(?i)(.*"email"\s*=\s*['"])([^\n\s'"]{5,200})([^\n]*)'''), 84, 'USER', None),
    (re.compile(r'(.*)(AKIA[A-Z0-9]{16})([^A-Z0-9][^\n]*)'), 1, 'USER', None),  # AWS Access Key
    (re.compile(r'''(?i)(.*\W)(''' + EMAIL_ADDR + r''')([^\n]*)'''), 85, 'USER', None),
    (re.compile(r'''(?i)(.*_USER\s*=\s*["'])([^\n\s"']{5,200})([^\n]*)'''), 86, 'USER', None),

]

# Regexes we use to exclude likely false-positive passwords
# Many of these are artefacts introduced by the typical context of the password detection regexes,
# such as filenames, html/dom fragments, and other common string constants.
non_password_regexes = [
    re.compile(r'''#[0-9a-f]{6}'''),  # web colour code
    re.compile(r'''0x[0-9a-f]{2}'''),  # hex
    re.compile(r'''(%n|%s|%y|%d|%m|%v)'''),  # c format specifiers
    re.compile(r'''(\\n|\\t|\\r)'''),  # escape codes
    re.compile(r'''(://)'''),  # url
    re.compile(r'''</?\w+>'''),  # xml or html tag
    re.compile(r'''[,.]\s'''),  # comma space or dot space
    re.compile(r'''[$@]\(\w+\)'''),  # interpolation
    re.compile(r'''[)}\],(\[{]$'''),
    re.compile(r'''(\$\(|\$\w+->)'''),  # php
    re.compile(r'''\$php'''),
    re.compile(r'''\):?$'''),  # ends in ')' or '):'
    re.compile(r'''\*\.'''),
    re.compile(r'''\.(dll|exe|so|doc|pdf|hml|css|js|gif|png|jpg|jpeg|sh)'''),
    re.compile(r'''\d+\.\d+\.\d+'''),  # version number
    re.compile(r'''\\[^\\]*\\'''),  # windows path
    re.compile(r'''\\[ux][0-9a-f]{2}'''),  # unicode or hex char
    re.compile(r'''(^\s|\s[^\s]*\s|\s\|\s|\s{4})'''),  # spaces; probably text
    re.compile(r'''{#?[a-z0-9_ ]+#?}'''),  # interpolation
    re.compile(r'''^[0\\][xX][0-9a-f]{4,}$'''),  # hex constant
    re.compile(r'''^(A+|X+|Z+|a+|x+|z+)$'''),  # AAAAAAA XXXXXXX etc
    re.compile(r'''^--'''),  # command line option flag
    re.compile(r'''^@\w+$'''),
    re.compile(r'''^[0-9:./ ]$'''),  # date/time or version number
    re.compile(r'''^[^a-z]+$'''),  # entirely non alpha
    re.compile(r'''^\$\w+$'''),
    re.compile(r'''^([a-z0-9][a-z0-9-_]{1,80}\.){2,}[a-z_]{1,14}$'''),  # looks like a fully qualified domain name
    re.compile(r'''^(}|\${|!join|false$|sha1-|sha256-|sha512-|split$|string\.|this\.|true$|user\.|xml|xsi)'''),  # begins with
    re.compile(r'''_[^_]*_'''),
    re.compile(r'''^('.*'|".*"|\$.*;|\\.*"|any|\$auth;|alias|await|hash|keyfile|new|nil|none|null|null;|pwd|user:pass|&gt)$'''),  # entire password is x
    re.compile(r'''(}|/|border|click|comments|focus|scroll|keydown|keyup|margin|pwd|resize|width|height|value)$'''),  # ends with
    re.compile(r'''(address|after|against|already|api.*key|associated|attribute|authentication|bearer|cannot)'''),
    re.compile(r'''(cdata|client|config|connect|contained|credentials|could|data\s*-|digest|either|element|enter\s|error|exists|extends|false|format|function)'''),
    re.compile(r'''(general|\.get|href|html|http|image|inactive|index|indicating|input|invalid|json|lambda|length|localhost|matches|md5|method|missing|mm:ss)'''),
    re.compile(r'''(option|passes|passphrase|\Wpassword\W|placeholder|plaintext|portion|property|provided|recovery|redacted|secret|settings|sha-1|should|source)'''),
    re.compile(r'''(string|text/|tlsv|token|true|type|uint|user_id|user_|username|utf-8|validation|value|var\.|video|wasn't|which|whose|xml|yyyy)'''),
]

# These regexes detect common 'placeholder' passwords used in test scripts that may not present a security risk (but then again, they may...)
non_password_regexes_strict = [
    re.compile(r'''(changeme|dummy|email|example|passwd|password|pswd|sample|secret)'''),
]


def get_passwords_from_line(fname, line):
    results = []

    for pwd_regex, rule_id, result_type, files_include in pwd_rules:
        if not douser:
            if result_type == 'USER':
                continue
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
            results = results + [(rule_id, prefix + g1, g2, g3, result_type)]
            remaining = g3
            prefix = g1 + g2
            if len(prefix) > 200: prefix = prefix[-200:]  # noqa
    return results


def is_not_a_password(pwd):
    # pwd is interpolation string, web rgb code, unicode char etc
    for npregex in non_password_regexes:
        if npregex.search(pwd.lower()):
            if vvv:
                eprint('Not a password: \'' + pwd + '\' because it matches regex \'' + str(npregex) + '\'')
            return True
    if not placeholder:
        for npregex in non_password_regexes_strict:
            if npregex.search(pwd.lower()):
                if vvv:
                    eprint('(Placeholder) Not a password: \'' + pwd + '\' because it matches regex \'' + str(npregex) + '\'')
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

        for rule_id, prefix, pwd, suffix, result_type in results:
            # check conditions under which we stop scoring the candidate password
            # allow very short passwords only if they're very common and bad (taken from the top1000 password list)
            if len(pwd) < 5: continue  # noqa
            if len(pwd) > 200: continue  # noqa
            if 'publickeytoken' in prefix.lower(): continue  # noqa
            # if 'example' in prefix.lower() or 'example' in suffix.lower(): continue  # noqa
            # if has_non_ascii(pwd): continue  # noqa
            if is_not_a_password(pwd) and pwd not in SHORT_BAD_PASSWORDS:
                continue  # noqa # ignore known non-password patterns
            outputs = outputs + [(rule_id, prefix + ':' + pwd + ':' + suffix, result_type)]
            if not allow_duplicates:
                break
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
    global wrote_result
    wrote_result = True
    while result_msg.endswith('\n'):
        result_msg = result_msg[0:-1]
    print(result_msg)


def do_line_cred_check(fname, line, line_num):
    try:
        results = check_line_password(fname, line)
        for rule_id, result, type in results:  # noqa
            msg = f"{fname}:{line_num}:{type}:Rule:{str(rule_id)}:{result}"
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
    if wrote_result:
        return 1
    else:
        return 0


def syntax():
    eprint(
        '''ccs.py : Code Credential Scanning Tool [ by Chris Anley ]
        Syntax: 

        Run from code root directory. Output is to stdout, errors and 'verbose' messages are to stderr.

        The default is to return fewer false-positives; use '-everything' for lots of false positives

        "Result Type" is USER (for a username/email/account id), or PASSWORD (for a password, auth token, cryptographic key)
        Password hashes and encrypted passwords are generally crackable, and are reported as 'PASSWORD'

        ccs.py [options]
        -a   : check all files, including binaries (i.e. files containing invalid utf-8 chars)
        -dupes : report all hits for a single line (default is to only report the first hit)
        -nosuppress : ignore suppression comments such as # noqa, at line and file level 
        -douser : Run USERNAME checks as well as PASSWORD / KEY checks
        -everything : Get all possible creds; equivalent to -nosuppress -douser -ns -sa -placeholder
        -ns  : no skip : don't skip files/directories that are irrelevant, like test, /vendor/, /node_modules/, .zip etc
        -p   : print progress
        -sa  : scan all files, not just recommended / code files
        -placeholder : Allow some likely 'placeholder' false positives, like 'password', 'example', 'dummy'
        -v   : quite verbose
        -vv  : annoyingly verbose
        -vvv : pointlessly verbose
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
allow_duplicates = False
placeholder = False
douser = False


def do_main():
    global a, v, vv, vvv, ns, sa, sc, print_progress, nosuppress, allow_duplicates, placeholder, douser
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
        if argv[i] == '-dupes':
            allow_duplicates = True
        if argv[i] == '-placeholder':
            placeholder = True
        if argv[i] == '-douser':
            douser = True
        if argv[i] == '-everything':
            douser = True
            nosuppress = True
            ns = True
            sa = True
            placeholder = True
    return do_checks()


def signal_handler(sig, frame):  # noqa
    os._exit(0)  # noqa


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    if do_main():
        sys.exit("CCS: Credentials were found\n")
