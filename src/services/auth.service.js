import { db } from '#config/db.js';
import logger from '#config/logger.js';
import { users } from '#models/user.model.js';
import bcrypt from 'bcryptjs';
import { eq } from 'drizzle-orm';

export const hashPassword = async password => {
  try {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
  } catch (error) {
    logger.error('Error hashing password: ', error);
    throw new Error('Error hashing password');
  }
};

export const createUser = async ({ name, email, password, role = 'user' }) => {
  try {
    const existsingUser = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1)
      .get();
    if (existsingUser) {
      throw new Error('User with this email already exists');
    }

    const hashedPassword = await hashPassword(password);
    const [newUser] = await db
      .insert(users)
      .values({ name, email, password: hashedPassword, role })
      .returning({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        created_at: users.created_at,
      })
      .execute();

    logger.info('New user created: ', newUser.email);

    return newUser;
  } catch (error) {
    logger.error('Error creating user: ', error);
    throw error;
  }
};
