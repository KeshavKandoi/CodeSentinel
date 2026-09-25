import express from 'express';
import multer from 'multer';
import jwt from 'jsonwebtoken';
const app = express();

app.post('/transfer', (req, res) => { const amount = req.body.amount; res.send('CODESENTINEL_PROOF_CSRF_ACCEPTED'); });
app.post('/webhook', (req, res) => { const event = req.body; res.send('CODESENTINEL_PROOF_WEBHOOK_ACCEPTED'); });
app.post('/profile', (req, res) => User.update(req.body).then(() => res.send('CODESENTINEL_PROOF_ADMIN_ASSIGNED')));
app.post('/upload', multer({ dest: 'uploads/' }).single('file'), (req, res) => res.send('CODESENTINEL_PROOF_UPLOAD_ACCEPTED'));
app.get('/jwt', (req, res) => res.send(jwt.decode(req.query.token)));
app.get('/session-cookie', (req, res) => res.cookie('session', 'fixture-secret', { secure: false, httpOnly: false, sameSite: 'none' }).send('ok'));
app.get('/cors', (req, res) => { res.setHeader('Access-Control-Allow-Origin', '*'); res.send('ok'); });
export default app;
