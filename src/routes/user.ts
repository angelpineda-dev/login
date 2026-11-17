import Router from 'express';
import authtenticateToken from '../middlewares/authMiddleware.ts'

const router = Router();

router.get('/me', authtenticateToken, async (req, res, next) => {
    const user = req?.user;
   
    try {
        return res.json({
            success: true,
            user: user
        });
    } catch (error: unknown) {
        next(error)
    }
})

export default router;