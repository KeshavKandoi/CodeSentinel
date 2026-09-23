export default async function handler(req, res) {
  if (req.method === 'GET') {
    res.status(200).json({ id: req.query.id });
  }
  if (req.method === 'DELETE') {
    const session = await getServerSession(req, res);
    if (!session?.user?.isAdmin) return res.status(403).end();
    res.status(204).end();
  }
}
