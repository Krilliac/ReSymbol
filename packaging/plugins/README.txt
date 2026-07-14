ReSymbol scans this directory for unpacked plugins.

Install each plugin in its own child directory with a plugin.toml manifest and its prebuilt
entrypoint. ReSymbol does not compile source code dropped here.

Current foundation releases discover and validate plugins but do not execute them yet. See
docs/install.md and the repository's docs/plugin-system.md for current status and safety guidance.

Start ReSymbol with --safe-mode to suppress third-party plugins. A plugin.disabled file inside a
plugin directory disables that plugin without deleting it.
