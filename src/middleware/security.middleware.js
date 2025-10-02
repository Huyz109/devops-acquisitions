import aj from '#config/arcjet.js';
import logger from '#config/logger.js';
import { slidingWindow } from '@arcjet/node';

const securityMiddleware = async (req, res, next) => {
  try {
    const role = req.user?.role || 'guest';

    let limit;
    let message;

    switch (role) {
      case 'admin':
        limit = 20; // High limit for admin users
        message =
          'Admin request limit exceeded (20 per minutes). Please try again later.';
        break;
      case 'user':
        limit = 10; // Moderate limit for regular users
        message =
          'User request limit exceeded (10 per minutes). Please try again later.';
        break;
      default:
        limit = 5; // Low limit for guests and unauthenticated users
        message =
          'Guest request limit exceeded (5 per minutes). Please try again later.';
        break;
    }

    const client = aj.withRule(
      slidingWindow({
        mode: 'LIVE', // Blocks requests. Use "DRY_RUN" to log only
        interval: '1m', // Check the rate limit every 1 minute
        max: limit, // Dynamic max requests based on user role
        name: `${role}-rate-limit`, // Name the rule based on user role
        message,
      })
    );

    const decision = await client.protect(req);

    if (decision.isDenied && decision.reason.isBot()) {
      logger.warn(
        `Blocked bot request from IP: ${req.ip}, User-Agent: ${req.get('User-Agent')}, path: ${req.path}`
      );
      return res
        .status(403)
        .json({ error: 'Forbidden', message: 'Automated requests are not allowed.' });
    }

    if (decision.isDenied && decision.reason.isShield()) {
      logger.warn(
        `Blocked shield request from IP: ${req.ip}, User-Agent: ${req.get('User-Agent')}, path: ${req.path}, method: ${req.method}`
      );
      return res
        .status(403)
        .json({ error: 'Forbidden', message: 'Shielded requests are not allowed.' });
    }

    if (decision.isDenied && decision.reason.isRateLimit()) {
      logger.warn(
        `Rate limit exceeded: ${req.ip}, User-Agent: ${req.get('User-Agent')}, path: ${req.path}, method: ${req.method}`
      );
      return res
        .status(403)
        .json({ error: 'Forbidden', message: 'Rate limit exceeded.' });
    }

    next();
  } catch (error) {
    logger.error('Arcjet Middleware Error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Some thing went wrong with security middleware',
    });
  }
};

export default securityMiddleware;
