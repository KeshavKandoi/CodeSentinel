import { Router } from 'express';

const router = Router();

router.get('/stats', (req, res) => res.json({ users: 1 }));
router
  .route('/settings')
  .get((req, res) => res.json({}))
  .put((req, res) => res.json({ saved: true }));

export default router;
