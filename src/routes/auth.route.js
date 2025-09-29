import { signIn, signOut, signUp } from '#controllers/auth.controller.js';
import express from 'express';

const router = express.Router();

router.post('/sign-up', signUp);

router.post('/login', signIn);

router.post('/logout', signOut);

export default router;