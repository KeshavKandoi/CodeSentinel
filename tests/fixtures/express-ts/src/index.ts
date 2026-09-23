import express from 'express';
import jwt from 'jsonwebtoken';

const app = express();
app.get('/', (req, res) => res.send('ok'));
app.listen(3000, () => console.log('listening on 3000'));
