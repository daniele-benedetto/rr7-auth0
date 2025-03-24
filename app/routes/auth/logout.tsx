import { redirect } from 'react-router';
import { auth0Service } from '../../services/auth0.server';
import { destroySession, getSession } from '../../services/sessions.server';

export async function loader({ request }: { request: Request }) {
  try {
    const session = await getSession(request.headers.get('Cookie'));
    
    if (!session) {
      throw new Error('No session found');
    }
    const logoutUrl = auth0Service.getLogoutUrl();
    const headers = new Headers();
    headers.append('Set-Cookie', await destroySession(session));
    return redirect(logoutUrl, { headers });
  } catch (error) {
    console.error('Error during logout:', error);
    return redirect(`/auth/login?returnTo=${encodeURIComponent(request.url)}`);
  }
}

export default function Logout() {
  return null;
}