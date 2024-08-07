import { Router } from 'express';
import validateJOI from '../middlewares/validateJOI.js';
import verifyToken from '../middlewares/verifyToken.js';
import { me, signin, signOut, signup } from '../controllers/auth.js';
import { userSchema, siginSchema } from '../joi/schemas.js';

const authRouter = Router();

authRouter.get('/me', verifyToken, me);
authRouter.post('/signin', validateJOI(siginSchema), signin);
authRouter.post('/signup', validateJOI(userSchema), signup);
authRouter.delete('/signout', signOut);

export default authRouter;
