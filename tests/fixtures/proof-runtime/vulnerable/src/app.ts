import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { exec } from 'node:child_process';
import axios from 'axios';

const app = express();

app.get('/path', (req, res) => {
  const filePath = path.join('/tmp/codesentinel-proof', String(req.query.path));
  res.send(fs.readFileSync(filePath, 'utf8'));
});

app.get('/redirect', (req, res) => res.redirect(String(req.query.url)));

app.get('/proxy', async (req, res) => {
  const response = await axios.get(String(req.query.url));
  res.send(response.data);
});

app.get('/search', async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE name = '${String(req.query.query)}'`);
  res.json(rows);
});

app.get('/run', (req, res) => exec(String(req.query.command), (_error, stdout) => res.send(stdout)));

app.get('/hello', (req, res) => res.send(String(req.query.q)));

export default app;
