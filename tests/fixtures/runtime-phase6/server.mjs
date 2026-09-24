import http from 'node:http';

const port = Number(process.env.PORT || 43127);

function user(req) {
  return req.headers['x-test-user'] || null;
}

const server = http.createServer((req, res) => {
  const path = new URL(req.url || '/', `http://${req.headers.host}`).pathname;
  const currentUser = user(req);
  const json = (status, value) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(value));
  };

  if (req.method === 'GET' && path === '/protected') {
    return currentUser ? json(200, { protected: true, user: currentUser }) : json(401, { error: 'auth required' });
  }
  if (req.method === 'GET' && path === '/public') return json(200, { public: true });
  if (req.method === 'POST' && path === '/admin/reset') return json(201, { reset: true });
  if (req.method === 'POST' && path === '/admin/role') {
    return req.headers['x-test-role'] === 'admin' ? json(201, { changed: true }) : json(403, { error: 'admin required' });
  }
  if (req.method === 'PUT' && path === '/documents/owner-secret') {
    return currentUser === 'owner' ? json(200, { updated: true }) : json(403, { error: 'owner required' });
  }
  if (req.method === 'PUT' && path === '/documents/idor-secret') return json(200, { updated: true });
  return json(404, { error: 'not found' });
});

server.listen(port, '127.0.0.1', () => {
  const address = server.address();
  const actualPort = typeof address === 'object' && address ? address.port : port;
  process.stdout.write(`runtime fixture listening on http://127.0.0.1:${actualPort}\n`);
});
