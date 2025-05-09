import { authConfig } from "./auth.config";
import { sql } from "@vercel/postgres";
import { z } from "zod";
import bcrypt from "bcrypt";
import Credentials from "next-auth/providers/credentials";
import NextAuth from "next-auth";
import type { User } from "@/app/lib/definitions";

// const sql = postgres(process.env.POSTGRES_URL!, { ssl: "require" });

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email = ${email}`;
    return user.rows[0] as User | undefined;
  } catch (error) {
    console.log("🚀 ~ getUser ~ error:", error);
    throw new Error("Failed to fetch user from database");
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({
            email: z.string().email(),
            password: z.string().min(6),
          })
          .safeParse(credentials);

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);

          if (!user) return null; // User not found

          const passwordMatch = await bcrypt.compare(password, user.password);

          if (passwordMatch) return user;
        }

        return null; // Invalid credentials
      },
    }),
  ],
});
