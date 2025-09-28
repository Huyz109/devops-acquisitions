import { signUp } from '#controllers/auth.controller.js';
import express from 'express';

const router = express.Router();

router.post('/sign-up', signUp);

router.post('/login', (req, res) => {
  // Handle login logic here
  res.status(200).send('Login successful');
});

router.post('/logout', (req, res) => {
  // Handle logout logic here
  res.status(200).send('Logout successful');
});

export default router;