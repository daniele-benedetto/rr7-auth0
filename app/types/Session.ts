import type { User } from './User';

export type SessionData = {
  accessToken: string;
  user: User;
};

export type SessionFlashData = {
  error: string;
};