import { auth } from "@/lib/auth";
import { headers } from "next/headers";
import { Pool } from "pg";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const TRIAL_DAYS = 7;

async function computeHmac(data: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function GET() {
  const session = await auth.api.getSession({ headers: await headers() });

  if (!session) {
    return Response.json({ authenticated: false, expired: false, daysLeft: 0 });
  }

  const { rows } = await pool.query(
    'SELECT "createdAt" FROM "User" WHERE "id" = $1',
    [session.user.id]
  );

  const createdAt = rows[0]?.createdAt;
  if (!createdAt) {
    return Response.json({ authenticated: true, expired: false, daysLeft: TRIAL_DAYS });
  }

  const trialEndsAt = new Date(new Date(createdAt).getTime() + TRIAL_DAYS * 24 * 60 * 60 * 1000);
  const now = new Date();
  const expired = now > trialEndsAt;
  const daysLeft = Math.max(0, Math.ceil((trialEndsAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)));

  // Signed cookie set karo taake middleware verify kar sake
  const secret = process.env.BETTER_AUTH_SECRET || "";
  const expiryTs = trialEndsAt.getTime().toString();
  const payload = `${expiryTs}|${session.user.id}`;
  const hmac = await computeHmac(payload, secret);
  const cookieValue = `${payload}|${hmac}`;

  const response = Response.json({ authenticated: true, expired, daysLeft, trialEndsAt });
  response.headers.set(
    "Set-Cookie",
    `trial_status=${encodeURIComponent(cookieValue)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${TRIAL_DAYS * 24 * 60 * 60}`
  );
  return response;
}
