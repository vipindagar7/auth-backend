import jwt from 'jsonwebtoken';
import { userModel as User } from '../models/userModel.js'
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config()

// create the jwt token for authencated user
export const createAuthToken = async (user) => {
    // creating access token for logged in user
    const accessToken = jwt.sign({ id: user._id, email: user.email },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: process.env.ACCESS_TOKEN_LIFETIME });
    // creating refresh token for logged in user
    const refreshToken = jwt.sign({ id: user._id, email: user.email },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: process.env.REFRESH_TOKEN_LIFETIME });

    // update refresh token in user db
    const update = await User.updateOne({ _id: user.id }, { refreshToken: refreshToken });

    return {
        accessToken,
        refreshToken
    };
};


// create a function which create a hash of a password
export const hashPassword = async (password) => {
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);
    return hashPassword;
};


// create a funciton which create a new and unique verificaiton token for the user verificaiton using uuidv4
export const createVerificationToken = async () => {
    return uuidv4();
};


// create a funciton which send account verificaiton mail to user 
export const sendAccountVerificationMail = async (receiverMail, token) => {
    const transporter = nodemailer.createTransport({
        // host: "gmail",
        service: "gmail",
        port: 465,
        secure: true, // true for port 465, false for other ports
        auth: {
            user: process.env.EMAIL,
            pass: process.env.EMAIL_PASSWORD,
        },
        tls: true
    });

    async function main() {
        const verificationLink = `${process.env.DOMAIN}/api/auth/verify/${token}`
        // send mail with defined transport object
        const info = await transporter.sendMail({
            from: `${process.env.YOUR_APP_NAME} ${process.env.EMAIL}`,
            to: receiverMail,
            subject: "Account Verification", // Subject line
            html: `
            <h2>Verify your account</h2>
            <p>Thank you for signing up! Please verify your account by clicking the link below:</p>
            <a href="${verificationLink}" style="display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none;">Verify Account</a>
            <br><br>
            <p>If the button doesn't work, click on this link:</p>
            <a href="${verificationLink}">${verificationLink}</a>
            <br><br>
            <p>If you did not sign up for this account, please ignore this email.</p>
        `, // html body
        });
    }
    main().catch(console.error);
};



export const sendRequestForgotPasswordMail = async (receiverMail, token) => {
    const transporter = nodemailer.createTransport({
        // host: "gmail",
        service: "gmail",
        port: 465,
        secure: true, // true for port 465, false for other ports
        auth: {
            user: process.env.EMAIL,
            pass: process.env.EMAIL_PASSWORD,
        },
        tls: true
    });

    async function main() {
        const link = `${process.env.DOMAIN}/auth/forgotPassword/${token}`
        // send mail with defined transport object
        const info = await transporter.sendMail({
            from: `${process.env.YOUR_APP_NAME} ${process.env.EMAIL}`,
            to: receiverMail,
            subject: "Forgot account password", // Subject line
            html: `
            <h2>Update your new password</h2>
            <p>Update your account password by clicking the link below:</p>
            <a href="${link}" style="display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none;">Reset Password</a>
            <br><br>
            <p>If the button doesn't work, click on this link:</p>
            <a href="${link}">${link}</a>
            <br><br>
            <p>If you did not request reset password for this account, please ignore this email.</p>
        `, // html body
        });
    }
    main().catch(console.error);
};


export const cookiesResponseOption = {
    httpOnly: true,
    secure: true,
}