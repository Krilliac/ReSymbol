ReSymbol scans this directory for unpacked plugins.

Install each plugin in its own child directory with a plugin.toml manifest and its prebuilt
entrypoint. ReSymbol does not compile source code dropped here.

The current alpha can execute eligible external-process and native C/C++ analysis plugins. Native
plugins are host OS/CPU artifacts and run through the resymbol-native-host sibling shipped beside
ReSymbol. Before first execution, review the plugin and run `resymbol plugin trust <id>` to approve
its exact directory fingerprint. Any change to the manifest, entrypoint, libraries, or data
invalidates that approval. Trust only plugins you would run directly: process separation protects
ReSymbol from a crash, but is not an operating-system sandbox and does not restrict the plugin's
ambient user access.

Start ReSymbol with --safe-mode to suppress third-party plugins. A plugin.disabled file inside a
plugin directory disables that plugin without deleting it or changing its fingerprint. Host-owned
trust and quarantine records are kept in the .resymbol child directory. See docs/install.md and
docs/plugin-system.md for current commands, limitations, and safety guidance.
