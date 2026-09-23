import Fastify from 'fastify';

const broken = Fastify();
broken.get('/broken', async (request, reply) => {
  return { oops: true
