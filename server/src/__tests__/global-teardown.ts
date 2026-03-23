import { pool } from '../db/connection';

export default async function globalTeardown() {
  // Close the database connection pool
  // This releases all active connections and lets the process exit cleanly
  await pool.end();
}
