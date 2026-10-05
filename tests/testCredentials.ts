export function testCredential(name: string): string {
  const key = `CODESENTINEL_TEST_${name}`;
  const value = process.env[key];
  if (!value) throw new Error(`Missing ${key}; populate the ignored .env file using .env.example.`);
  return value;
}
