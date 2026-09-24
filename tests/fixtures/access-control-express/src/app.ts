import express from 'express';

const app = express();
app.use(express.json());

// Public route: no guard at all.
app.get('/public/ping', (req, res) => res.json({ ok: true }));

// Authenticated only, reads a document by id, no ownership comparison.
// admin: this comment mentions admin/role/token and must NOT affect analysis.
app.get('/documents/:id', authenticate, (req, res) => {
  const { id } = req.params;
  const doc = db.findById(id);
  res.json(doc);
});

// Ownership-protected: authenticated + explicit ownership comparison before writing.
app.put('/documents/:id', authenticate, (req, res) => {
  const { id } = req.params;
  const doc = db.findById(id);
  if (doc.ownerId !== req.user.id) {
    return res.status(403).json({ error: 'forbidden' });
  }
  doc.save();
  res.json(doc);
});

// IDOR candidate: authenticated, loads by id, deletes, no ownership comparison.
app.delete('/documents/:id', authenticate, (req, res) => {
  const { id } = req.params;
  const doc = db.findById(id);
  doc.delete();
  res.sendStatus(204);
});

// Role-protected admin route with a real guard.
app.get('/admin/reports', authenticate, requireRole('admin'), (req, res) => res.json([]));

// Missing-authentication candidate: administrative path, no guard.
app.post('/admin/reset', (req, res) => res.json({ reset: true }));

// Decoy identifiers containing 'admin'/'role'/'token' that must NOT be misdetected
// as real guards -- they are plain string values, never used as middleware/decorators.
const userRoleDescription = 'admin-style humor, not a real role check';
const tokenExampleForDocs = 'token=EXAMPLE_NOT_A_REAL_CHECK';

function authenticate(req, res, next) {
  req.user = { id: 'stub' };
  next();
}

function requireRole(role) {
  return (req, res, next) => next();
}

export default app;
