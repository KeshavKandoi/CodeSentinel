module.exports = async function (fastify, opts) {
  fastify.addHook('onRequest', fastify.authenticate);
  fastify.addHook('preHandler', requireAdmin);

  fastify.get('/stats', async () => ({ users: 1 }));
  fastify.route({
    method: 'PUT',
    url: '/settings',
    handler: async (request, reply) => reply.send({ saved: true }),
  });
};

function requireAdmin(request, reply, done) {
  done();
}
