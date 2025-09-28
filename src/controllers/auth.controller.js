import logger from '#config/logger.js';
import { cookies } from '#utils/cookies.js';
import { formatValidationErrors } from '#utils/format.js';
import { jwtToken } from '#utils/jwt.js';
import { createUser } from '../services/auth.service';
import { signUpSchema } from '../validations/auth.validation';

export const signUp = async (req, res, next) => {
  try {
    const validationResult = signUpSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Invalid input',
        message: formatValidationErrors(validationResult.error),
      });
    }

    const { name, email, password, role } = validationResult.data;

    // Auth service
    const user = await createUser({ name, email, password, role });

    const token = jwtToken.sign({ id: user.id, email: user.email, role: user.role });

    cookies.set(res, 'token', token);

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    logger.error('Sign up error: ', error);

    if (error.message === 'User with this email already exists') {
      return res.status(409).json({ error: 'Email already exists' });
    }

    next(error);
  }
};
