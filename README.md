# Rainbow Bridge

A local Chrome bookmarks organizer focused on turning large bookmark folders into usable dashboards.

## What it does

- Reads the Chrome `Bookmarks` file
- Regroups bookmarks into cleaner folders
- Exports bookmark collections as local HTML navigation pages
- Builds a dedicated `ai中转站` dashboard with platform fingerprinting
- Separates links into `NewAPI`, `Sub2API`, manual exclusions, review-needed links, and probe failures

## Main files

- `classify_chrome_bookmarks.py`: bookmark organizer and dashboard generator
- `chrome_bookmarks_dashboard.html`: full dashboard export
- `ai_community_dashboard.html`: specialized AI relay site dashboard

## Usage

Generate the full dashboard:

```bash
python classify_chrome_bookmarks.py --export-html
```

Generate only the `ai中转站` page:

```bash
python classify_chrome_bookmarks.py --export-html --folder-name ai中转站 --html-output ai_community_dashboard.html
```

Apply bookmark reorganization back to Chrome:

```bash
python classify_chrome_bookmarks.py --apply
```

## Notes

- The script uses live HTTP probing for stronger platform identification.
- Probe cache and temporary research folders are ignored from Git.
