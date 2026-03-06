import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient({
  baseURL: process.env.NEXT_PUBLIC_APP_URL || "https://pdf-7trail.vercel.app",
});

export const { signIn, signUp, signOut, useSession } = authClient;
