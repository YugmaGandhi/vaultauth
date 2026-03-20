import { userRepository } from '../repositories/user.repository';
import { auditRepository } from '../repositories/audit.repository';
import { passwordService } from './password.service';
import { ConflictError } from '../utils/errors';
import { SafeUser } from '../utils/types';
import { createLogger } from '../utils/logger';

const log = createLogger('AuthService');

type RegisterParams = {
  email: string;
  password: string;
  ipAddress?: string;
  userAgent?: string;
};

type RegisterResult = {
  user: SafeUser;
  message: string;
};

export class AuthService {
  async register(params: RegisterParams): Promise<RegisterResult> {
    const { email, password, ipAddress, userAgent } = params;

    log.info({ email }, 'Registering new user');

    // Step 1 — Check if email already exists
    const existing = await userRepository.findByEmail(email);
    if (existing) {
      log.warn({ email }, 'Registration failed — email already exists');
      throw new ConflictError(
        'EMAIL_ALREADY_EXISTS',
        'An account with this email already exists'
      );
    }

    // Step 2 — Hash the password
    const passwordHash = await passwordService.hash(password);

    // Step 3 — Create the user
    const user = await userRepository.create({
      email: email.toLowerCase().trim(),
      passwordHash,
    });

    // Step 4 — Write audit log
    // Fire and forget — don't await, don't block the response
    void auditRepository.create({
      userId: user.id,
      eventType: 'user_registered',
      ipAddress,
      userAgent,
      metadata: { email },
    });

    log.info({ userId: user.id, email }, 'User registered successfully');

    return {
      user,
      message:
        'Account created successfully. Please check your email to verify your account.',
    };
  }
}

export const authService = new AuthService();
