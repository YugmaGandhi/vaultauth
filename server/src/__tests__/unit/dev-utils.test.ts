// ── Mock logger ──────────────────────────────────────────
jest.mock('../../utils/logger', () => ({
  createLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }),
}));

// ── Mock DB chain ────────────────────────────────────────
// Drizzle uses a fluent API: db.select().from(table).where(cond)
// We need a mock that tracks calls and returns configurable results
const mockUpdateSetWhere = jest.fn().mockResolvedValue(undefined);
const mockSet = jest.fn();
const mockUpdate = jest.fn();

const mockSelectFromWhere = jest.fn();
const mockSelect = jest.fn();
const mockFrom = jest.fn();

const mockInsert = jest.fn();
const mockValues = jest.fn();
const mockOnConflictDoNothing = jest.fn().mockResolvedValue(undefined);

jest.mock('../../db/connection', () => ({
  db: {
    update: (...args: unknown[]) => {
      mockUpdate(...args);
      return {
        set: (...setArgs: unknown[]) => {
          mockSet(...setArgs);
          return { where: mockUpdateSetWhere };
        },
      };
    },
    select: (...args: unknown[]) => {
      mockSelect(...args);
      return {
        from: (...fromArgs: unknown[]) => {
          mockFrom(...fromArgs);
          return { where: mockSelectFromWhere };
        },
      };
    },
    insert: (...args: unknown[]) => {
      mockInsert(...args);
      return {
        values: (...valuesArgs: unknown[]) => {
          mockValues(...valuesArgs);
          return { onConflictDoNothing: mockOnConflictDoNothing };
        },
      };
    },
  },
}));

jest.mock('../../db/schema', () => ({
  users: { email: 'users.email' },
  roles: { name: 'roles.name' },
  userRoles: 'user_roles_table',
}));

jest.mock('drizzle-orm', () => ({
  eq: jest.fn((...args: unknown[]) => args),
}));

jest.mock('dotenv', () => ({
  config: jest.fn(),
}));

// ── Mock process.exit and console ────────────────────────
const mockExit = jest
  .spyOn(process, 'exit')
  .mockImplementation(() => undefined as never);
const mockConsoleLog = jest
  .spyOn(console, 'log')
  .mockImplementation(() => undefined);
const mockConsoleError = jest
  .spyOn(console, 'error')
  .mockImplementation(() => undefined);

beforeEach(() => {
  jest.clearAllMocks();
  mockSelectFromWhere.mockResolvedValue([]);
  mockUpdateSetWhere.mockResolvedValue(undefined);
});

afterAll(() => {
  mockExit.mockRestore();
  mockConsoleLog.mockRestore();
  mockConsoleError.mockRestore();
});

describe('dev-verify.ts', () => {
  it('should exit with error when no email provided', () => {
    const originalArgv = process.argv;
    process.argv = ['node', 'dev-verify.ts'];

    jest.isolateModules(() => {
      require('../../utils/dev-verify');
    });

    expect(mockConsoleError).toHaveBeenCalledWith(
      expect.stringContaining('Usage')
    );
    expect(mockExit).toHaveBeenCalledWith(1);

    process.argv = originalArgv;
  });

  it('should verify email and exit with success', async () => {
    const originalArgv = process.argv;
    process.argv = ['node', 'dev-verify.ts', 'test@example.com'];

    jest.isolateModules(() => {
      require('../../utils/dev-verify');
    });

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(mockUpdate).toHaveBeenCalled();
    expect(mockSet).toHaveBeenCalledWith({ isVerified: true });
    expect(mockConsoleLog).toHaveBeenCalledWith(
      expect.stringContaining('test@example.com')
    );
    expect(mockExit).toHaveBeenCalledWith(0);

    process.argv = originalArgv;
  });
});

describe('dev-make-admin.ts', () => {
  it('should exit with error when no email provided', () => {
    const originalArgv = process.argv;
    process.argv = ['node', 'dev-make-admin.ts'];

    jest.isolateModules(() => {
      require('../../utils/dev-make-admin');
    });

    expect(mockConsoleError).toHaveBeenCalledWith(
      expect.stringContaining('Usage')
    );
    expect(mockExit).toHaveBeenCalledWith(1);

    process.argv = originalArgv;
  });

  it('should exit with error when user not found', async () => {
    const originalArgv = process.argv;
    process.argv = ['node', 'dev-make-admin.ts', 'nobody@example.com'];

    mockSelectFromWhere.mockResolvedValue([]);

    jest.isolateModules(() => {
      require('../../utils/dev-make-admin');
    });

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(mockConsoleError).toHaveBeenCalledWith(
      expect.stringContaining('User not found')
    );
    expect(mockExit).toHaveBeenCalledWith(1);

    process.argv = originalArgv;
  });

  it('should exit with error when admin role not found', async () => {
    const originalArgv = process.argv;
    process.argv = ['node', 'dev-make-admin.ts', 'user@example.com'];

    mockSelectFromWhere
      .mockResolvedValueOnce([{ id: 'user-uuid', email: 'user@example.com' }])
      .mockResolvedValueOnce([]);

    jest.isolateModules(() => {
      require('../../utils/dev-make-admin');
    });

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(mockConsoleError).toHaveBeenCalledWith(
      expect.stringContaining('Admin role not found')
    );
    expect(mockExit).toHaveBeenCalledWith(1);

    process.argv = originalArgv;
  });

  it('should promote user to admin and exit with success', async () => {
    const originalArgv = process.argv;
    process.argv = ['node', 'dev-make-admin.ts', 'user@example.com'];

    mockSelectFromWhere
      .mockResolvedValueOnce([{ id: 'user-uuid', email: 'user@example.com' }])
      .mockResolvedValueOnce([{ id: 'admin-role-uuid', name: 'admin' }]);

    jest.isolateModules(() => {
      require('../../utils/dev-make-admin');
    });

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(mockInsert).toHaveBeenCalled();
    expect(mockValues).toHaveBeenCalledWith({
      userId: 'user-uuid',
      roleId: 'admin-role-uuid',
    });
    expect(mockConsoleLog).toHaveBeenCalledWith(
      expect.stringContaining('admin')
    );
    expect(mockExit).toHaveBeenCalledWith(0);

    process.argv = originalArgv;
  });
});
