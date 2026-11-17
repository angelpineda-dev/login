import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { db } from '../prisma/db.ts'
import type { User } from "../types/auth.ts"
import AppError from '../errors/AppError.ts';
import { authMessages } from '../core/userMessages/auth.ts';

const registerUser = async (data: User) => {

    const { password, confirmed_password, ...newData } = data;

    const isPasswordMatch = password === confirmed_password;

    if (!isPasswordMatch || !password || !confirmed_password) {
        throw new Error(authMessages.CONFIRM_PASSWORD);
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 15);

        const user = await db.orm.public.User.select('id').create({
            ...newData,
            password: hashedPassword
        });

        if (!user) {
            throw new AppError(authMessages.ERROR_SAVING_USER, 500)
        }

        return user;
    } catch (error) {
        throw new AppError(authMessages.ERROR_SAVING_USER, 500)
    }

}

const validateLogin = async (email: string, password: string) => {
    const JWT_SECRET = process.env.JWT_SECRET;
    const user = await db.orm.public.User.where({ email }).first();

    if (!JWT_SECRET) {
        throw new AppError(authMessages.SERVER_MISSING_CONFIG, 500)
    }

    if (!user) {
        throw new AppError(authMessages.INVALID_CREDENTIALS);
    }

    try {
        const isValidPassword = await bcrypt.compare(password, user.password);

        if (!isValidPassword) {
            throw new AppError(authMessages.INVALID_CREDENTIALS);
        }

        const token = jwt.sign({
            id: user.id,
            role: user.role
        }, JWT_SECRET, { expiresIn: '4h' })

        return token;
    } catch (error) {
        throw new AppError(authMessages.INVALID_CREDENTIALS);
    }
}

export {
    registerUser,
    validateLogin
}