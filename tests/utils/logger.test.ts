import { logger } from '../../src/utils/logger';

describe('Logger', () => {
  let consoleErrorSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
  });

  it('logs all levels because AORP keeps debug logging enabled', () => {
    logger.error('error message');
    logger.warn('warn message');
    logger.info('info message');
    logger.debug('debug message');

    expect(consoleErrorSpy).toHaveBeenCalledTimes(4);
    expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('[ERROR] error message'));
    expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('[WARN] warn message'));
    expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('[INFO] info message'));
    expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('[DEBUG] debug message'));
  });

  it('includes an ISO timestamp and log level', () => {
    logger.info('test message');

    const logCall = consoleErrorSpy.mock.calls[0][0];
    const timestampMatch = logCall.match(/\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\]/);

    expect(timestampMatch).toBeTruthy();
    expect(new Date(timestampMatch[1]).toISOString()).toBe(timestampMatch[1]);
    expect(logCall).toContain('[INFO] test message');
  });

  it('formats messages with util.format', () => {
    logger.info('User %s logged in with id %d', 'john', 123);

    expect(consoleErrorSpy).toHaveBeenCalledWith(
      expect.stringContaining('User john logged in with id 123'),
    );
  });

  it('formats objects, arrays, null, and undefined values', () => {
    logger.info('Object: %j, Array: %j', { foo: 'bar' }, [1, 2, 3]);
    logger.info('Values:', undefined, null);

    expect(consoleErrorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Object: {"foo":"bar"}, Array: [1,2,3]'),
    );
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Values: undefined null'),
    );
  });

  it('does not throw on circular object references', () => {
    const circular: Record<string, unknown> = { a: 1 };
    circular.self = circular;

    expect(() => logger.info('Circular:', circular)).not.toThrow();
    expect(consoleErrorSpy).toHaveBeenCalled();
  });

  it('handles empty messages', () => {
    logger.info('');

    expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringMatching(/\[INFO\]\s*$/));
  });
});
