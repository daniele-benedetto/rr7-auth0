import dotenv from 'dotenv';
import { createCookieSessionStorage } from 'react-router';
import type { SessionData, SessionFlashData } from '../types/Session';

dotenv.config();

const { SESSION_SECRET } = process.env;
if (!SESSION_SECRET) throw new Error('Missing session secret.');

const { getSession, commitSession, destroySession } = createCookieSessionStorage<SessionData, SessionFlashData>({
  cookie: {
    name: '__session',
    httpOnly: true,
    maxAge: 60 * 60 * 24 * 7,
    path: '/',
    sameSite: 'lax',
    secrets: [SESSION_SECRET],
    secure: process.env.NODE_ENV === 'production',
  },
});

export { commitSession, destroySession, getSession };