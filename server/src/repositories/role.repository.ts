import { eq, and } from 'drizzle-orm';
import { db } from '../db/connection';
import { roles, userRoles, permissions, rolePermissions } from '../db/schema';
import { createLogger } from '../utils/logger';

const log = createLogger('RoleRepository');

export class RoleRepository {
  async findAll() {
    log.debug('Finding all roles');
    return db.select().from(roles);
  }

  async findById(id: string) {
    const [role] = await db.select().from(roles).where(eq(roles.id, id));
    return role ?? null;
  }

  async findByName(name: string) {
    const [role] = await db.select().from(roles).where(eq(roles.name, name));
    return role ?? null;
  }

  async assignToUser(
    userId: string,
    roleId: string,
    assignedBy?: string
  ): Promise<void> {
    await db
      .insert(userRoles)
      .values({ userId, roleId, assignedBy })
      .onConflictDoNothing();
  }

  async removeFromUser(userId: string, roleId: string): Promise<void> {
    await db
      .delete(userRoles)
      .where(and(eq(userRoles.userId, userId), eq(userRoles.roleId, roleId)));
  }

  async findUserRolesWithPermissions(userId: string) {
    return db
      .select({
        roleName: roles.name,
        permissionName: permissions.name,
      })
      .from(userRoles)
      .innerJoin(roles, eq(userRoles.roleId, roles.id))
      .leftJoin(rolePermissions, eq(roles.id, rolePermissions.roleId))
      .leftJoin(permissions, eq(rolePermissions.permissionId, permissions.id))
      .where(eq(userRoles.userId, userId));
  }
}

export const roleRepository = new RoleRepository();
