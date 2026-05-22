# Terminal Output Examples

This directory is reserved for generated terminal screenshots and recordings.

Milestone 3 includes a Rich CLI and Textual TUI. After installing locally, run:

```bash
cleantrace init --yes
cleantrace profile create --slug default --username exampleuser --consent
cleantrace scan username exampleuser --profile default --depth quick
cleantrace link github --profile default
cleantrace scan github --profile default
cleantrace tui
```

The generated output uses calm Rich panels, tables, status indicators, colour-coded severity, and a final "Top 5 actions to reduce exposure" panel.
