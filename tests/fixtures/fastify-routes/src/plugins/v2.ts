import { FastifyInstance } from 'fastify';

export async function v2Routes(fastify: FastifyInstance) {
  fastify.get('/items', async () => []);
  fastify.get('/search', {
    schema: {
      querystring: { type: 'object', properties: { q: { type: 'string' }, page: { type: 'integer' } }, required: ['q'] },
    },
  }, async (request) => request.query);
}
