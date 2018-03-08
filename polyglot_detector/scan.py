from .plugins import ALL_PLUGINS
from .polyglot_level import PolyglotLevel


def scan(filename) -> {str: PolyglotLevel}:
    results = {}
    for plugin in ALL_PLUGINS:
        result = plugin.check(filename)
        if result is not None:
            results[plugin.FILE_EXTENSION] = result
    return results
