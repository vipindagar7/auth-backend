// routes/userRoutes.js
import express from 'express';
import { changePassword, forgotPassword, getUser, loginController, logout, refreshToken, requestForgotPassword, signupController, verify } from '../controllers/userController.js';
import { authenticatedMiddleware } from '../middleware/fetchUser.js';

// creating Router instance
const router = express.Router();

// create post route for signup user
router.post('/signup', signupController);


// create post route for login user
router.post('/login', loginController);


// create a get route to verify mail
router.get('/verify/:token', verify);

// create post change password route to change passsword 
router.post('/changePassword', authenticatedMiddleware, changePassword);

// create a post route for request to reset password
router.post('/forgotPassword', requestForgotPassword);

// create a post route for request to reset password
router.post('/forgotPassword/:token', forgotPassword);

// create a post route to get user details
router.post('/getUser', authenticatedMiddleware, getUser);

// create a post route to refresh the expired access token
router.post('/refreshToken', refreshToken);

// create a post route to refresh the expired access token
router.post('/logout', authenticatedMiddleware, logout);


export default router;
