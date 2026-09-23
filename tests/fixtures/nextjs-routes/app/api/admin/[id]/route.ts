import { NextResponse } from 'next/server';

export async function GET(_request: Request, context: { params: { id: string } }) {
  const token = await getToken();
  return NextResponse.json({ id: context.params.id, token });
}

export async function PATCH(request: Request) {
  const form = await request.formData();
  return NextResponse.json({ ok: true, form });
}
