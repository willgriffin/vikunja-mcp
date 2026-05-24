import { ConfigurationManager, Environment, ConfigurationError } from '../../src/config';

describe('ConfigurationManager', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.NODE_ENV;
    delete process.env.JEST_WORKER_ID;
    ConfigurationManager.reset();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    ConfigurationManager.reset();
  });

  it('detects the Jest test environment', async () => {
    process.env.JEST_WORKER_ID = '1';

    const config = await ConfigurationManager.getInstance().getConfiguration();

    expect(config.environment).toBe(Environment.TEST);
    expect(config.logging.level).toBe('error');
    expect(config.logging.environment).toBe(Environment.TEST);
  });

  it('detects production from NODE_ENV', async () => {
    process.env.NODE_ENV = 'production';

    const config = await ConfigurationManager.getInstance().getConfiguration();

    expect(config.environment).toBe(Environment.PRODUCTION);
    expect(config.logging.level).toBe('info');
  });

  it('defaults to development outside test and production', async () => {
    const config = await ConfigurationManager.getInstance().getConfiguration();

    expect(config.environment).toBe(Environment.DEVELOPMENT);
    expect(config.logging.level).toBe('debug');
  });

  it('allows explicit environment override', async () => {
    const config = await ConfigurationManager.getInstance({
      environment: Environment.PRODUCTION,
    }).getConfiguration();

    expect(config.environment).toBe(Environment.PRODUCTION);
  });

  it('does not read legacy scattered environment variables', async () => {
    process.env.VIKUNJA_URL = 'https://tasks.example.com';
    process.env.VIKUNJA_API_TOKEN = 'tk_test123';
    process.env.LOG_LEVEL = 'warn';

    const config = await ConfigurationManager.getInstance().getConfiguration();

    expect(config.auth.vikunjaUrl).toBeUndefined();
    expect(config.auth.vikunjaToken).toBeUndefined();
    expect(config.logging.level).toBe('debug');
  });

  it('allows explicit source overrides', async () => {
    const config = await ConfigurationManager.getInstance({
      sources: {
        auth: {
          vikunjaUrl: 'https://tasks.example.com',
          vikunjaToken: 'tk_test123',
          mcpMode: 'server',
        },
        logging: {
          level: 'warn',
        },
        rateLimiting: {
          default: {
            requestsPerMinute: 42,
          },
        },
      },
    }).getConfiguration();

    expect(config.auth.vikunjaUrl).toBe('https://tasks.example.com');
    expect(config.auth.vikunjaToken).toBe('tk_test123');
    expect(config.auth.mcpMode).toBe('server');
    expect(config.logging.level).toBe('warn');
    expect(config.rateLimiting.default.requestsPerMinute).toBe(42);
  });

  it('caches the loaded configuration for an instance', async () => {
    const manager = ConfigurationManager.getInstance();

    const first = await manager.getConfiguration();
    const second = await manager.getConfiguration();

    expect(first).toBe(second);
  });

  it('returns typed configuration sections', async () => {
    const manager = ConfigurationManager.getInstance({
      sources: {
        auth: { vikunjaUrl: 'https://tasks.example.com' },
        logging: { level: 'warn' },
      },
    });

    await expect(manager.getAuthConfig()).resolves.toMatchObject({
      vikunjaUrl: 'https://tasks.example.com',
    });
    await expect(manager.getLoggingConfig()).resolves.toMatchObject({
      level: 'warn',
    });
    await expect(manager.getRateLimitConfig()).resolves.toHaveProperty('default.requestsPerMinute');
  });

  it('reports fixed AORP feature flags through isFeatureEnabled', () => {
    const manager = ConfigurationManager.getInstance();

    expect(manager.isFeatureEnabled('enableServerSideFiltering')).toBe(true);
    expect(manager.isFeatureEnabled('enableAdvancedMetrics')).toBe(false);
    expect(manager.isFeatureEnabled('unknown')).toBe(false);
  });

  it('wraps invalid configuration sources in ConfigurationError', async () => {
    const manager = ConfigurationManager.getInstance({
      sources: {
        rateLimiting: {
          default: {
            requestsPerMinute: -1,
          },
        },
      },
    });

    await expect(manager.getConfiguration()).rejects.toThrow(ConfigurationError);
  });

  it('resets the singleton instance for tests', () => {
    const first = ConfigurationManager.getInstance();
    ConfigurationManager.reset();
    const second = ConfigurationManager.getInstance();

    expect(first).not.toBe(second);
  });
});
