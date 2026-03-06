import { NextRequest, NextResponse } from "next/server";

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

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Public routes — auth nahi chahiye
  if (
    pathname.startsWith("/signin") ||
    pathname.startsWith("/signup") ||
    pathname.startsWith("/upgrade") ||
    pathname.startsWith("/api/auth") ||
    pathname.startsWith("/api/trial-status") ||
    pathname.startsWith("/_next") ||
    pathname.startsWith("/favicon")
  ) {
    return NextResponse.next();
  }

  // Session cookie check
  const sessionToken =
    request.cookies.get("better-auth.session_token")?.value ||
    request.cookies.get("__Secure-better-auth.session_token")?.value;

  if (!sessionToken) {
    return NextResponse.redirect(new URL("/signin", request.url));
  }

  // Trial cookie server-side verify karo
  const trialCookie = request.cookies.get("trial_status")?.value;
  if (trialCookie) {
    try {
      const decoded = decodeURIComponent(trialCookie);
      const parts = decoded.split("|");
      if (parts.length === 3) {
        const [expiryTs, userId, hmac] = parts;
        const secret = process.env.BETTER_AUTH_SECRET || "";
        const expectedHmac = await computeHmac(`${expiryTs}|${userId}`, secret);
        if (hmac === expectedHmac && Date.now() > parseInt(expiryTs)) {
          return NextResponse.redirect(new URL("/upgrade", request.url));
        }
      }
    } catch {
      // Invalid cookie — let through, TrialBanner handle karega
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|public).*)"],
};
