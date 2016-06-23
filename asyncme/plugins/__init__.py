

from . import challenge_handlers


def _load_plugins():

    import pkg_resources

    # Challenge Handlers
    entry = 'asyncme.plugins.challenge_handlers'
    for plugin in pkg_resources.iter_entry_points(entry):
        if hasattr(challenge_handlers, plugin.name):
            print("Plugin name {} conflicts with module".format(plugin.name))
            continue
        try:
            setattr(challenge_handlers, plugin.name, plugin.load())
        except ImportError:
            print("Plugin {} failed to load".format(plugin.name))


_load_plugins()

del _load_plugins
