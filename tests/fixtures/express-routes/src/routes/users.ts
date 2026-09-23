import { Router } from 'express';
import { authenticate, requireRole } from '../middleware/auth';

const router = Router();

router.get('/', (req, res) => res.json([]));
router.get('/:id', (req, res) => {
  const { id } = req.params;
  res.json({ id });
});
router.post('/', authenticate, (req, res) => {
  const { name, email } = req.body;
  res.status(201).json({ name, email });
});
router.delete('/:id', authenticate, requireRole('admin'), deleteUser);

function deleteUser(req, res) {
  res.sendStatus(204);
}

export default router;
