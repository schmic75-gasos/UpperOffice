// Simple Nextcloud cleanup prototype using WebDAV
const express = require('express');
const basicAuth = require('express-basic-auth');
const { createClient } = require('webdav');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const pMap = require('p-map');

const CONFIG_PATH = path.resolve(__dirname, 'config.json');
if (!fs.existsSync(CONFIG_PATH)) {
  console.log('Create config.json based on config.example.json and rerun.');
  process.exit(1);
}
const config = JSON.parse(fs.readFileSync(CONFIG_PATH));

const db = new Database(path.join(__dirname, 'metadata.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY,
  path TEXT,
  size INTEGER,
  mtime INTEGER,
  sha1 TEXT
);
CREATE INDEX IF NOT EXISTS idx_sha1 ON files(sha1);
CREATE INDEX IF NOT EXISTS idx_path ON files(path);
`);

const client = createClient(config.webdav.url, {
  username: config.webdav.user,
  password: config.webdav.password
});

async function listAllFiles(remotePath = '/') {
  // Recursively list files. webdav Client's getDirectoryContents can list per directory
  const stack = [remotePath];
  const files = [];

  while (stack.length) {
    const p = stack.pop();
    let items;
    try {
      items = await client.getDirectoryContents(p);
    } catch (err) {
      console.error('Error listing', p, err.message);
      continue;
    }
    for (const it of items) {
      if (it.type === 'directory') {
        stack.push(it.filename);
      } else if (it.type === 'file') {
        files.push(it);
      }
    }
  }
  return files;
}

function streamSha1FromStream(stream) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha1');
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

async function processFile(it) {
  // it: { filename, basename, size, lastmod ... }
  // skip zero-sized files?
  const existing = db.prepare('SELECT id, sha1 FROM files WHERE path = ?').get(it.filename);
  if (existing && existing.sha1) return { updated: false };

  try {
    const stream = await client.createReadStream(it.filename);
    const sha1 = await streamSha1FromStream(stream);
    const stmt = db.prepare('INSERT OR REPLACE INTO files (id, path, size, mtime, sha1) VALUES ((SELECT id FROM files WHERE path = ?), ?, ?, ?, ?)');
    stmt.run(it.filename, it.filename, it.size || 0, new Date(it.lastmod).getTime(), sha1);
    return { updated: true, sha1 };
  } catch (err) {
    console.error('Error processing', it.filename, err.message);
    return { updated: false, error: err.message };
  }
}

async function scanAndStore() {
  console.log('Listing files...');
  const files = await listAllFiles(config.webdav.basePath || '/');
  console.log('Total files found:', files.length);

  // process in parallel with concurrency
  const concurrency = config.scanConcurrency || 4;
  await pMap(files, processFile, { concurrency });
  console.log('Scan finished.');
}

function getDuplicates() {
  const rows = db.prepare('SELECT sha1, COUNT(*) as cnt FROM files GROUP BY sha1 HAVING cnt > 1').all();
  const groups = rows.map(r => {
    const members = db.prepare('SELECT id, path, size, mtime FROM files WHERE sha1 = ? ORDER BY mtime DESC').all(r.sha1);
    return { sha1: r.sha1, count: r.cnt, files: members };
  });
  return groups;
}

async function deletePath(remotePath) {
  await client.deleteFile(remotePath);
  db.prepare('DELETE FROM files WHERE path = ?').run(remotePath);
}

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
if (config.http.basicUser && config.http.basicPass) {
  app.use(basicAuth({ users: { [config.http.basicUser]: config.http.basicPass }, challenge: true }));
}

// API routes
app.get('/api/scan', async (req, res) => {
  try {
    await scanAndStore();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/dups', (req, res) => {
  res.json(getDuplicates());
});

app.post('/api/delete', async (req, res) => {
  const { path } = req.body;
  if (!path) return res.status(400).json({ error: 'Missing path' });
  try {
    await deletePath(path);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Simple UI
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'ui.html'));
});

app.get('/app.js', (req, res) => res.type('application/javascript').sendFile(path.join(__dirname, 'app.js')));

const PORT = config.http.port || 3000;
app.listen(PORT, () => console.log(`nc-cleanup running at http://localhost:${PORT}`));
