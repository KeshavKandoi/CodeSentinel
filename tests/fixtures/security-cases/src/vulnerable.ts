import express from 'express';
import cors from 'cors';
import multer from 'multer';
import axios from 'axios';
import { exec } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import serialize from 'node-serialize';

const app = express();
const apiKey = 'sk_live_abcdef1234567890';
const upload = multer({ dest: 'uploads/' });

app.use(cors({ origin: '*' }));
app.set('x-powered-by', true);
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

app.get('/admin/users', (req, res) => res.json({ ok: true }));
app.get('/profile/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.json(user);
});

app.get('/search', async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
  res.json(rows);
});

app.get('/mongo', async (req, res) => {
  const docs = await Users.find({ $where: req.query.filter });
  res.json(docs);
});

app.get('/run', (req, res) => {
  exec(`git log --author=${req.query.author}`, (_error, stdout) => res.send(stdout));
});

app.get('/download', (req, res) => {
  fs.createReadStream(path.join('/srv/files', req.query.name as string)).pipe(res);
});

app.get('/proxy', async (req, res) => {
  const response = await axios.get(req.query.url as string);
  res.send(response.data);
});

app.get('/hello', (req, res) => {
  res.send(`<h1>${req.query.name}</h1>`);
});

app.get('/go', (req, res) => res.redirect(String(req.query.url)));

app.post('/upload', upload.single('file'), (req, res) => res.json(req.file));

app.post('/state', (req, res) => {
  const state = serialize.unserialize(req.body.state);
  res.json(state);
});

app.get('/jwt', (req, res) => {
  jwt.verify(req.query.token, 'public', { ignoreExpiration: true });
  res.send('ok');
});

app.listen(3000);
