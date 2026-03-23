import dotenv from 'dotenv';
import path from 'path';

export default function globalSetup() {
  // Load .env.test before any test runs
  dotenv.config({
    path: path.resolve(__dirname, '../../.env.test'),
    override: true,
  });
}
