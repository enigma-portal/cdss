"""Create an allowlisted source-only archive; never include runtime data/secrets."""

import argparse
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = ('app', 'static', 'templates', 'tests', 'scripts')
SOURCE_FILES = ('run.py', 'wsgi.py', 'config.py', 'requirements.txt', 'README.md', '.env.example')
FORBIDDEN_PARTS = {'venv', '.venv', '__pycache__', 'data', '.git', 'credentials'}
FORBIDDEN_SUFFIXES = {'.db', '.sqlite', '.sqlite3', '.key', '.pem', '.p12',
                      '.pfx', '.secret', '.pyc', '.zip', '.log'}


def source_members(root=ROOT):
    """Explicit allowlist; adding a new top-level path cannot leak it."""
    for name in SOURCE_FILES:
        path = root / name
        if path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root.resolve()):
            yield path
    for name in SOURCE_DIRS:
        folder = root / name
        if not folder.is_dir():
            continue
        for path in folder.rglob('*'):
            relative = path.relative_to(root)
            if (path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root.resolve())
                    and not any(part.lower() in FORBIDDEN_PARTS for part in relative.parts)
                    and path.suffix.lower() not in FORBIDDEN_SUFFIXES
                    and not path.name.lower().startswith(('.env', 'credentials'))):
                yield path


def export_source(destination, root=ROOT):
    destination = Path(destination).resolve()
    if destination.suffix.lower() != '.zip':
        raise ValueError('Source export path must end in .zip')
    if destination.exists():
        raise FileExistsError('Refusing to overwrite an existing source archive')
    members = list(source_members(root))
    if not members:
        raise ValueError('No source files were found')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(destination, 'w', compression=ZIP_DEFLATED) as archive:
        for path in members:
            archive.write(path, path.relative_to(root).as_posix())
    return len(members)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Export CDSS source without runtime secrets')
    parser.add_argument('destination', help='Output .zip path')
    args = parser.parse_args()
    print(f'Exported {export_source(args.destination)} source files.')
