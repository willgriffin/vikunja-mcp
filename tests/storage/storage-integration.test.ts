import {
  createFilterStorage,
  getAllStorageStats,
  healthCheckAllStorage,
  migrateMemoryToPersistent,
  storageManager,
} from '../../src/storage';

describe('Storage Integration', () => {
  beforeEach(async () => {
    await storageManager.clearAll();
  });

  afterAll(async () => {
    await storageManager.clearAll();
  });

  it('creates session-scoped in-memory filter storage', async () => {
    const storage = await createFilterStorage('session-1');

    const filter = await storage.create({
      name: 'Open Tasks',
      filter: 'done = false',
      isGlobal: true,
    });

    await expect(storage.get(filter.id)).resolves.toMatchObject({
      id: filter.id,
      name: 'Open Tasks',
      filter: 'done = false',
    });
  });

  it('reuses storage for the same session', async () => {
    const first = await createFilterStorage('session-2');
    const filter = await first.create({
      name: 'Priority',
      filter: 'priority > 2',
      isGlobal: false,
    });

    const second = await createFilterStorage('session-2');

    await expect(second.get(filter.id)).resolves.toMatchObject({
      name: 'Priority',
    });
  });

  it('isolates filters across sessions', async () => {
    const first = await createFilterStorage('session-a');
    const second = await createFilterStorage('session-b');

    await first.create({
      name: 'Only A',
      filter: 'done = false',
      isGlobal: false,
    });

    await expect(first.list()).resolves.toHaveLength(1);
    await expect(second.list()).resolves.toHaveLength(0);
  });

  it('reports stats for active memory sessions', async () => {
    const first = await createFilterStorage('stats-a');
    const second = await createFilterStorage('stats-b');
    await first.create({ name: 'A', filter: 'done = false', isGlobal: false });
    await second.create({ name: 'B', filter: 'done = true', isGlobal: true });

    const stats = await getAllStorageStats();

    expect(stats.persistentSessions).toEqual([]);
    expect(stats.totalSessions).toBe(2);
    expect(stats.totalFilters).toBe(2);
    expect(stats.memorySessions.map(session => session.filterCount)).toEqual([1, 1]);
  });

  it('reports healthy in-memory storage', async () => {
    await createFilterStorage('health-session');

    const health = await healthCheckAllStorage();

    expect(health.overall).toBe('healthy');
    expect(health.memory.healthy).toBe(true);
    expect(health.memory.sessionCount).toBe(1);
    expect(health.persistent.healthy).toBe(true);
  });

  it('keeps migration as a no-op in the simplified storage implementation', async () => {
    const storage = await createFilterStorage('migration-session');
    await storage.create({
      name: 'Metadata',
      description: 'Preserved in memory',
      filter: 'priority > 1 && done = false',
      projectId: 456,
      isGlobal: false,
    });

    const result = migrateMemoryToPersistent();

    expect(result).toEqual({
      success: true,
      migratedSessions: 0,
      migratedFilters: 0,
      errors: [],
    });
    await expect(storage.list()).resolves.toHaveLength(1);
  });
});
