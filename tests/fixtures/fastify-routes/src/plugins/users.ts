import { FastifyInstance } from 'fastify';

export default async function usersPlugin(fastify: FastifyInstance) {
  fastify.get('/', async () => []);

  fastify.get<{ Params: { id: string } }>('/:id', {
    schema: { params: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] } },
  }, async (request) => {
    const { id } = request.params;
    return { id };
  });

  fastify.post('/', {
    preHandler: [fastify.authenticate],
    schema: {
      body: { type: 'object', properties: { name: { type: 'string' }, email: { type: 'string' } }, required: ['name'] },
    },
  }, async (request, reply) => reply.code(201).send(request.body));

  fastify.delete('/:id', { preHandler: fastify.auth([fastify.authenticate, fastify.verifyAdmin]) }, deleteUser);
}

async function deleteUser(request: any, reply: any) {
  return reply.code(204).send();
}
