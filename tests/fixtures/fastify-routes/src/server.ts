import Fastify from 'fastify';
import jwt from '@fastify/jwt';
import multipart from '@fastify/multipart';
import usersPlugin from './plugins/users';
import adminPlugin from './plugins/admin';
import { v2Routes } from './plugins/v2';
import dynamicPlugin from './plugins/dynamic';

const app = Fastify({ logger: true });
const API_PREFIX = '/api';

// app.get('/commented-out', async () => 'never registered');
app.register(jwt, { secret: 'demo' });
app.register(multipart);

app.decorate('authenticate', async (request: any, reply: any) => {
  await request.jwtVerify();
});

app.addHook('onRequest', async (request) => {
  request.log.info('incoming request');
});

app.get('/health', async () => ({ ok: true }));
app.get('/health', async () => ({ ok: true, duplicate: true }));

app.post('/login', async (request, reply) => {
  const { username, password } = request.body as any;
  return reply.code(200).send({ token: 'demo', username });
});

app.post('/avatar', { preHandler: [app.authenticate] }, async (request, reply) => {
  const data = await request.file();
  return reply.send({ ok: !!data });
});

app.route({
  method: ['GET', 'POST'],
  url: '/multi',
  handler: async (request, reply) => reply.send({ multi: true }),
});

app.register(usersPlugin, { prefix: '/users' });
app.register(adminPlugin, { prefix: '/admin' });
app.register(async (api) => {
  api.get('/ping', async () => 'pong');
  api.register(v2Routes, { prefix: '/v2' });
}, { prefix: API_PREFIX });
app.register(async (secure) => {
  secure.addHook('onRequest', app.authenticate);
  secure.get('/me', async (request) => request.user);
  secure.register(async (inner) => {
    inner.get('/inner', async () => 'inner');
  }, { prefix: '/deep' });
}, { prefix: '/secure' });
app.register(dynamicPlugin, { prefix: getPrefix() });

app.listen({ port: 3000 });
