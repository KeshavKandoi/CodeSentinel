import { Router } from 'express';
import { buildPath } from '../util';

export const dynamicRouter = Router();

dynamicRouter.get('/static-in-dynamic', (req, res) => res.json({}));
dynamicRouter.get(buildPath('reports'), (req, res) => res.json([]));
