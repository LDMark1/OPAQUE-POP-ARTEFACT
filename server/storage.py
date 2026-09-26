"""Persistent OPAQUE setup/records; exclusive process ownership on POSIX.
Sessions deliberately never survive restart. Keep this directory private and back
up the setup and password records together. This is research-artefact storage.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import sqlite3


class Store:
    def __init__(self, directory, setup_factory):
        directory = Path(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.stat().st_mode & 0o077:
            raise RuntimeError('state directory must have mode 0700')
        self.guard = open(directory / 'process.lock', 'a+b')
        try:
            fcntl.flock(self.guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.guard.close()
            raise RuntimeError('state directory is already in use; run exactly one worker') from None
        self.path = directory / 'credentials.sqlite3'
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        if self.path.stat().st_mode & 0o077:
            self.close()
            raise RuntimeError('credential database must have mode 0600')
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS setup (id INTEGER PRIMARY KEY CHECK(id=1), value BLOB NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_file BLOB NOT NULL)')
            row = db.execute('SELECT value FROM setup WHERE id=1').fetchone()
            if row is None:
                self.setup = bytes(setup_factory())
                db.execute('INSERT INTO setup VALUES(1, ?)', (self.setup,))
            else:
                self.setup = row[0]

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path)
        try:
            with db:
                yield db
        finally:
            db.close()

    def get(self, username):
        with self.connect() as db:
            row = db.execute('SELECT password_file FROM users WHERE username=?', (username,)).fetchone()
        return row[0] if row else None

    def register(self, username, password_file):
        try:
            with self.connect() as db:
                db.execute('INSERT INTO users VALUES (?, ?)', (username, bytes(password_file)))
        except sqlite3.IntegrityError:
            return False
        return True

    def close(self):
        self.guard.close()
