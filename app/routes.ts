import { type RouteConfig, index, layout, prefix, route } from '@react-router/dev/routes';
export default [
  layout('routes/layouts/authLayout.tsx', [
    index('routes/index.tsx'),
  ]),
  ...prefix('auth', [
    route('login', 'routes/auth/login.tsx'),
    route('logout', 'routes/auth/logout.tsx'),
    route('callback', 'routes/auth/callback.tsx'),
  ]),
] satisfies RouteConfig;