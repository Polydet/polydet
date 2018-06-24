from .magic import magic_scan
from .plugins import ALL_PLUGINS
from . import PolyglotLevel, rules


def scan(filename, use_magic=False) -> {str: {}}:
    r = rules.get()
    matches = r.match(filename)
    results = {}
    for plugin in ALL_PLUGINS:
        namespace_matches = [m for m in matches if m.namespace == plugin.FILE_EXTENSION]
        matches_dict = {m.rule: m for m in namespace_matches}
        result = plugin.check_with_matches(filename, matches_dict)
        if result is not None:
            results[plugin.FILE_EXTENSION] = result
    if use_magic:
        for ext in magic_scan(filename):
            results[ext] = results.get(ext, PolyglotLevel())
    return results
