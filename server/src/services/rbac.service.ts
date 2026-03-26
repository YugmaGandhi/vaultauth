import { roleRepository } from '../repositories/role.repository';
import { userRepository } from '../repositories/user.repository';
import { createLogger } from '../utils/logger';

const log = createLogger('RBACService');

type UserRolesAndPermissions = {
  roles: string[];
  permissions: string[];
};

export class RBACService {
  async getUserRolesAndPermissions(
    userId: string
  ): Promise<UserRolesAndPermissions> {
    log.debug({ userId }, 'Fetching user roles and permissions');

    const result = await roleRepository.findUserRolesWithPermissions(userId);

    const roleSet = new Set<string>();
    const permissionSet = new Set<string>();

    for (const row of result) {
      roleSet.add(row.roleName);
      if (row.permissionName) permissionSet.add(row.permissionName);
    }

    return {
      roles: Array.from(roleSet),
      permissions: Array.from(permissionSet),
    };
  }

  async assignDefaultRole(userId: string): Promise<void> {
    log.debug({ userId }, 'Assigning default role');

    const userRole = await roleRepository.findByName('user');
    if (!userRole) {
      log.error('Default user role not found — run migrations');
      return;
    }

    await roleRepository.assignToUser(userId, userRole.id);
    log.debug({ userId }, 'Default role assigned');
  }

  async getAllRoles() {
    return roleRepository.findAll();
  }

  async assignRoleToUser(
    userId: string,
    roleId: string,
    assignedBy: string
  ): Promise<void> {
    const user = await userRepository.findById(userId);
    if (!user) throw new Error('USER_NOT_FOUND');

    const role = await roleRepository.findById(roleId);
    if (!role) throw new Error('ROLE_NOT_FOUND');

    await roleRepository.assignToUser(userId, roleId, assignedBy);
  }

  async removeRoleFromUser(userId: string, roleId: string): Promise<void> {
    await roleRepository.removeFromUser(userId, roleId);
  }

  hasPermission(userPermissions: string[], required: string): boolean {
    return userPermissions.includes(required);
  }
}

export const rbacService = new RBACService();
