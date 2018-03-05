from .plugins import ALL_PLUGINS
from .polyglot_level import PolyglotLevel


def scan(file) -> [(str, PolyglotLevel)]:
    results = []
    for plugin in ALL_PLUGINS:
        result = plugin.check(file)
        if result is not None:
            results.append((plugin.FILE_EXTENSION, result))
    return results
