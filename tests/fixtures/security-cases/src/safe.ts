import express from 'express';
import cors from 'cors';
import multer from 'multer';
import fs from 'node:fs';
import path from 'node:path';

const app = express();
const apiKey = process.env.API_KEY;
const placeholderSecret = 'changeme';
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 1024 * 1024 },
  fileFilter: (_req, file, cb) => cb(null, file.mimetype === 'image/png')
});

app.use(cors({ origin: 'https://example.com' }));

app.get('/admin/users', requireAuth, (req, res) => res.json({ ok: true }));
app.get('/profile/:id', requireAuth, async (req, res) => {
  if (req.user.id !== req.params.id) return res.status(403).end();
  const user = await User.findById(req.params.id);
  res.json(user);
});

app.get('/search', async (req, res) => {
  const rows = await db.query('SELECT * FROM users WHERE name = $1', [String(req.query.name)]);
  res.json(rows);
});

app.get('/download', requireAuth, (req, res) => {
  const fileName = allowlistedName(req.query.name);
  fs.createReadStream(path.join('/srv/files', fileName)).pipe(res);
});

app.post('/upload', requireAuth, upload.single('file'), (req, res) => res.json(req.file));

function requireAuth(_req: any, _res: any, next: any) { next(); }
function allowlistedName(input: unknown) { return String(input).replace(/[^a-z0-9.]/gi, ''); }
