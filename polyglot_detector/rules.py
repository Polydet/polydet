import yara

from .plugins import ALL_PLUGINS

__COMPILED_RULES = None


def get():
    if __COMPILED_RULES is None:
        __compile_rules()
    return __COMPILED_RULES


def load(filename):
    global __COMPILED_RULES
    __COMPILED_RULES = yara.load(filepath=filename)


def load_or_compile(filename):
    """Try to load the rules from a file, or compile them if the file is not found"""
    global __COMPILED_RULES
    try:
        with open(filename, 'rb') as rulefile:
            __COMPILED_RULES = yara.load(file=rulefile)
    except FileNotFoundError:
        __compile_rules()
        save(filename)


def save(filename):
    get().save(filepath=filename)


def __compile_rules():
    global __COMPILED_RULES
    rule_sources = {}
    for plugin in ALL_PLUGINS:
        rule_sources[plugin.FILE_EXTENSION] = plugin.RULES
    __COMPILED_RULES = yara.compile(sources=rule_sources)