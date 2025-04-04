import { redirect } from 'react-router';
import { auth0Service } from '~/services/auth0.server';
import { commitSession, getSession } from '~/services/sessions.server';
import type { Route } from './+types/callback';

export function meta() {
  return [
    { title: 'rr7-auth0 Callback page' },
    { name: 'description', content: 'Callback page' }
  ];
}

export async function loader({ request }: Route.LoaderArgs) {
  try {
    const url = new URL(request.url);
    const searchParams = new URLSearchParams(url.search);

    const code = searchParams.get('code');
    const error = searchParams.get('error');
    const errorDescription = searchParams.get('error_description');

    if (error) {
      throw new Error(`Auth0 error: ${error} ${errorDescription}`);
    }

    if (!code) {
      throw new Error('Missing code from Auth0');
    }

    const { accessToken, userInfo } = await auth0Service.exchangeCodeForToken(code);

    const session = await getSession(request.headers.get('Cookie'));

    if (!session) {
      throw new Error('No session found');
    }

    session.set('user', userInfo);
    session.set('accessToken', accessToken);

    const headers = new Headers({
      'Set-Cookie': await commitSession(session),
    });

    return redirect('/', {
      headers,
    });
  } catch (error: unknown) {
    console.error('Authentication error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';

    const searchParams = new URLSearchParams({
      error: 'auth_error',
      message: errorMessage,
    });

    return redirect(`/auth/login?${searchParams.toString()}`);
  }
}

export default function Callback() {
  return null;
}
