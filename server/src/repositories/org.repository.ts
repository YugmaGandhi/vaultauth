import { eq, and, count } from 'drizzle-orm';
import { db } from '../db/connection';
import { organizations, orgMembers } from '../db/schema';
import { NewOrganization, Organization } from '../utils/types';
import { createLogger } from '../utils/logger';

const log = createLogger('OrgRepository');

export class OrgRepository {
  // ── Create ────────────────────────────────────────────
  async create(data: NewOrganization): Promise<Organization> {
    log.debug({ slug: data.slug }, 'Creating organization');

    const [org] = await db.insert(organizations).values(data).returning();
    return org;
  }

  // ── Find by ID ────────────────────────────────────────
  async findById(id: string): Promise<Organization | null> {
    const [org] = await db
      .select()
      .from(organizations)
      .where(eq(organizations.id, id));

    return org ?? null;
  }

  // ── Find by slug ──────────────────────────────────────
  async findBySlug(slug: string): Promise<Organization | null> {
    const [org] = await db
      .select()
      .from(organizations)
      .where(eq(organizations.slug, slug));

    return org ?? null;
  }

  // ── List orgs for a user ──────────────────────────────
  async findByUserId(
    userId: string
  ): Promise<(Organization & { role: string; joinedAt: Date })[]> {
    const rows = await db
      .select({
        id: organizations.id,
        name: organizations.name,
        slug: organizations.slug,
        logoUrl: organizations.logoUrl,
        metadata: organizations.metadata,
        createdBy: organizations.createdBy,
        createdAt: organizations.createdAt,
        updatedAt: organizations.updatedAt,
        role: orgMembers.role,
        joinedAt: orgMembers.joinedAt,
      })
      .from(orgMembers)
      .innerJoin(organizations, eq(orgMembers.orgId, organizations.id))
      .where(eq(orgMembers.userId, userId));

    return rows;
  }

  // ── Count orgs created by a user ──────────────────────
  async countByCreator(userId: string): Promise<number> {
    const [result] = await db
      .select({ count: count() })
      .from(organizations)
      .where(eq(organizations.createdBy, userId));

    return result.count;
  }

  // ── Update ────────────────────────────────────────────
  async update(
    id: string,
    data: Partial<Pick<Organization, 'name' | 'slug' | 'logoUrl' | 'metadata'>>
  ): Promise<Organization> {
    const [org] = await db
      .update(organizations)
      .set({ ...data, updatedAt: new Date() })
      .where(eq(organizations.id, id))
      .returning();

    return org;
  }

  // ── Delete ────────────────────────────────────────────
  async delete(id: string): Promise<void> {
    await db.delete(organizations).where(eq(organizations.id, id));
  }

  // ── Add member ────────────────────────────────────────
  async addMember(
    orgId: string,
    userId: string,
    role: string = 'member'
  ): Promise<void> {
    await db.insert(orgMembers).values({ orgId, userId, role });
  }

  // ── Find membership ───────────────────────────────────
  async findMembership(
    orgId: string,
    userId: string
  ): Promise<{ id: string; role: string } | null> {
    const [row] = await db
      .select({ id: orgMembers.id, role: orgMembers.role })
      .from(orgMembers)
      .where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, userId)));

    return row ?? null;
  }
}

export const orgRepository = new OrgRepository();
