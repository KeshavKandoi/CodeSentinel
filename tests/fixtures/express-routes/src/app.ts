import express from 'express';
import multer from 'multer';
import { authenticate, requireRole } from './middleware/auth';
import usersRouter from './routes/users';
import adminRouter from './routes/admin';
import { apiRouter } from './routes/api';
import { dynamicRouter } from './routes/dynamic';

const app = express();
const upload = multer({ dest: 'uploads/' });
const API_PREFIX = '/api';

// app.get('/commented-out', (req, res) => res.send('never registered'));
app.set('trust proxy', 1);
app.use(express.json());

app.get('/health', (req, res) => res.json({ ok: true }));
app.get('/health', (req, res) => res.json({ ok: true, duplicate: true }));
app.get('env');

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  res.status(200).json({ token: 'demo', username });
});

app.post('/avatar', authenticate, upload.single('avatar'), (req, res) => {
  res.json({ name: req.file });
});

app.use('/users', usersRouter);
app.use('/admin', authenticate, requireRole('admin'), adminRouter);
app.use(API_PREFIX, apiRouter);
app.use(getBase() + '/dyn', dynamicRouter);

app.listen(3000);
