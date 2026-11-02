"""Tell application code from tests and from text.

A scanner that matches algorithm names finds them in test names, translation
files, documentation and sample data as readily as in code. On OWASP Juice
Shop, "RSA" in Chinese translations of a challenge description and "MD5" in a
test's title were reported beside the MD5 the application really uses. The
report lists code first and the rest apart, since a name in text is usually a
mention rather than a use.
"""

import re

CODE, TEST, TEXT = "code", "test", "text"
# Set by the merge, not by path: a line of code that names the algorithm only
# in a file extension, a URL or a query string.
MENTION = "mention"

_TEST = re.compile(
    r"(^|/)(tests?|spec|specs|__tests__|__mocks__|it|e2e|cypress|testdata|test-data|fixtures?)(/|$)"
    r"|[._-](test|spec)\.[a-z0-9]+$|Tests?\.(java|kt|cs|scala)$|_test\.(go|py|rb)$|(^|/)test_[^/]+\.py$",
    re.I)
_TEXT = re.compile(
    r"(^|/)(i18n|l10n|locales?|translations?|docs?|documentation)(/|$)"
    r"|\.(md|adoc|rst|txt|html?)$"
    r"|(^|/)(data|static|seeds?)/.*\.(ya?ml|json|csv)$",
    re.I)


def kind(path: str) -> str:
    if not path:
        return CODE
    path = path.split("!/", 1)[0]  # an archive's member is judged by the archive
    if _TEST.search(path):
        return TEST
    if _TEXT.search(path):
        return TEXT
    return CODE
