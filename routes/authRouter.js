import { Router } from 'express';
import verifyToken from '../middlewares/verifyToken.js';
import validateJOI from '../middlewares/validateJOI.js';
import { me, signin, signup } from '../controllers/auth.js';
import { userSchema, siginSchema } from '../joi/schemas.js';

const authRouter = Router();

authRouter.get('/me', verifyToken, me);
authRouter.post('/signin', validateJOI(siginSchema), signin);
authRouter.post('/signup', validateJOI(userSchema), signup);

export default authRouter;
