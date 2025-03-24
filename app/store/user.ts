import { create } from 'zustand';
import { devtools } from 'zustand/middleware';
import type { User } from '~/types/User';

interface UserStore {
  user: User | null;
  accessToken: string | null;
  setUser: (user: User) => void;
  setAccessToken: (accessToken: string) => void;
}

export const useUserStore = create<UserStore>()(
  devtools((set) => ({
    user: null,
    accessToken: null,
    setUser: (user: User) => set({ user }),
    setAccessToken: (accessToken: string) => set({ accessToken }),
  }))
);