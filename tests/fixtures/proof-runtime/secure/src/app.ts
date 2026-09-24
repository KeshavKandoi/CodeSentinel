import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';

const app = express();
const root = '/tmp/codesentinel-proof';

app.get('/path', (req, res) => {
  const requested = path.resolve(root, String(req.query.path));
  if (!requested.startsWith(`${root}${path.sep}`)) return res.status(400).send('safe path rejected');
  res.send(fs.readFileSync(requested, 'utf8'));
});

app.get('/redirect', (req, res) => {
  const destination = String(req.query.url);
  if (!destination.startsWith('/')) return res.status(400).send('safe redirect rejected');
  res.redirect(destination);
});

app.get('/proxy', async (req, res) => {
  const target = new URL(String(req.query.url));
  if (target.hostname !== '127.0.0.1' && target.hostname !== 'localhost') return res.status(403).send('safe SSRF destination rejected');
  res.send('safe local destination');
});

app.get('/search', async (req, res) => {
  const rows = await db.query('SELECT * FROM users WHERE name = $1', [String(req.query.query)]);
  res.json(rows);
});

app.get('/run', (req, res) => execFile('printf', [String(req.query.command)], (_error, stdout) => res.send(stdout)));

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character] ?? character));
}

app.get('/hello', (req, res) => res.send(escapeHtml(String(req.query.q))));

export default app;
