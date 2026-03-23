// DEV ONLY — manually verify a user email for testing
// Usage: npx ts-node src/utils/dev-verify.ts test@example.com
import { db } from '../db/connection';
import { users } from '../db/schema';
import { eq } from 'drizzle-orm';
import dotenv from 'dotenv';

dotenv.config();

const email = process.argv[2];

if (!email) {
  console.error('Usage: npx ts-node src/utils/dev-verify.ts <email>');
  process.exit(1);
}

async function verify() {
  await db
    .update(users)
    .set({ isVerified: true })
    .where(eq(users.email, email));

  console.log(`✅ Verified email: ${email}`);
  process.exit(0);
}

void verify();
