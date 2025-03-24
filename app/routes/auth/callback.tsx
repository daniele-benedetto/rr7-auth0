import { redirect } from 'react-router';
import { auth0Service } from '../../services/auth0.server';
import { commitSession, getSession } from '../../services/sessions.server';

export async function loader({ request }: { request: Request }) {
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
      throw new Error('Missing code or state from Auth0');
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
    return redirect('/', { headers });
  } catch (error) {
    console.error('Authentication error:', error);
    return {
      error: 'Authentication error',
      errorDescription: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

export default function Callback() {
  return null;
}