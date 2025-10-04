import express from 'express';
import logger from './config/logger.js';
import helmet from 'helmet';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRouter from '#routes/auth.route.js';
import securityMiddleware from './middleware/security.middleware.js';

const app = express();

// Middleware setup
app.use(helmet());
app.use(cors());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  morgan('combined', { stream: { write: msg => logger.info(msg.trim()) } })
);

app.use(securityMiddleware);

// Basic routes
app.get('/', (req, res) => {
  logger.info('Hello world');
  res.status(200).send('Hello, World!');
});

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

app.get('/api', (req, res) => {
  res.status(200).json({ message: 'API is running!' });
});

// Auth routes
app.use('/api/auth', authRouter);

// Global error handler
app.use((err, req, res) => {
  logger.error(err);
  res.status(500).json({ error: 'Internal Server Error' });
});

export default app;
