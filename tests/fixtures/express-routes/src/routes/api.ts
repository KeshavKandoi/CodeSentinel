import { Router } from 'express';

export const apiRouter = Router();
const v2 = Router();

apiRouter.get('/items', (req, res) => res.json([]));
apiRouter.get('/search', (req, res) => {
  const { q, page } = req.query;
  res.json({ q, page });
});
v2.get('/ping', (req, res) => res.send('pong'));

apiRouter.use('/v2', v2);
