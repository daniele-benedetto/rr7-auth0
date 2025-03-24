import { useEffect } from 'react';
import type { LoaderFunctionArgs } from 'react-router';
import { Outlet, redirect } from 'react-router';
import { useUserStore } from '../../store/user';
import { auth0Service } from '../../services/auth0.server';
import type { User } from '../../types/User';

export async function loader({ request }: LoaderFunctionArgs) {
  try {
    const isAuthenticated = await auth0Service.verifySession(request);
    if (!isAuthenticated) {
      throw new Error('Unauthorized');
    }
    const accessToken = await auth0Service.getAccessToken(request);
    const userInfo = await auth0Service.getUserInfo(accessToken);
    return {
      accessToken,
      userInfo,
    };
  } catch (e) {
    return redirect(`/auth/login?returnTo=${encodeURIComponent(request.url)}`);
  }
}

export default function AuthLayout({ loaderData }: { loaderData: { accessToken: string; userInfo: User } }) {
  const { accessToken, userInfo } = loaderData;
  const { setUser, setAccessToken } = useUserStore();
  useEffect(() => {
    setUser(userInfo);
    setAccessToken(accessToken);
  }, [userInfo, accessToken]);
  return <Outlet />;
}