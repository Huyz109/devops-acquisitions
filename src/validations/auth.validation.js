import z from 'zod';

export const signUpSchema = z.object({
  name: z.string().min(2).max(255).trim(),
  email: z.email().max(255).toLowerCase().trim(),
  password: z.string().min(6).max(100).trim(),
  role: z.enum(['user', 'admin']).default('user'),
});

export const loginSchema = z.object({
  email: z.email().max(255).toLowerCase().trim(),
  password: z.string().min(6).max(100).trim(),
});