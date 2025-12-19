import { SignJWT, jwtVerify } from "jose"

if (!process.env.NEXTAUTH_SECRET) {
  throw new Error("NEXTAUTH_SECRET environment variable is required")
}

const ADMIN_SECRET = new TextEncoder().encode(process.env.NEXTAUTH_SECRET)

// Create admin JWT token
export async function createAdminToken() {
  return await new SignJWT({ role: "admin", isAdmin: true })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("24h")
    .sign(ADMIN_SECRET)
}

// Verify admin JWT token
export async function verifyAdminToken(token: string) {
  try {
    const { payload } = await jwtVerify(token, ADMIN_SECRET)
    return payload.isAdmin === true
  } catch {
    return false
  }
}
