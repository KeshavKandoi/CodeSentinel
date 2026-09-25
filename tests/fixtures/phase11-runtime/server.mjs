import http from 'node:http';
import { URL } from 'node:url';

const secure = process.env.CODESENTINEL_SECURE === '1';
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1');
  let body = '';
  for await (const chunk of req) body += chunk;
  const send = (status, text, headers = {}) => { res.writeHead(status, { 'content-type': 'text/plain', ...headers }); res.end(text); };
  if (url.pathname === '/transfer') return send(secure ? 403 : 200, secure ? 'csrf token required' : 'CODESENTINEL_PROOF_CSRF_ACCEPTED');
  if (url.pathname === '/webhook') return send(secure ? 401 : 200, secure ? 'signature required' : 'CODESENTINEL_PROOF_WEBHOOK_ACCEPTED');
  if (url.pathname === '/profile') return send(secure ? 200 : 200, secure ? 'role ignored' : 'CODESENTINEL_PROOF_ADMIN_ASSIGNED');
  if (url.pathname === '/upload') return send(secure ? 415 : 200, secure ? 'file type rejected' : 'CODESENTINEL_PROOF_UPLOAD_ACCEPTED');
  if (url.pathname === '/jwt') return send(secure ? 401 : 200, secure ? 'invalid token' : 'CODESENTINEL_PROOF_JWT_ACCEPTED');
  if (url.pathname === '/session-cookie') return send(200, 'ok', { 'set-cookie': secure ? 'session=fixture-secret; Secure; HttpOnly; SameSite=Lax' : 'session=fixture-secret' });
  if (url.pathname === '/cors') return send(200, 'ok', secure ? { 'access-control-allow-origin': 'https://app.example' } : { 'access-control-allow-origin': '*' });
  send(404, 'not found');
});
server.listen(Number(process.env.PORT), '127.0.0.1');
