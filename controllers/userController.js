import { userModel as User } from '../models/userModel.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();
import { createAuthToken, createVerificationToken, hashPassword, sendAccountVerificationMail, sendRequestForgotPasswordMail } from './utils.js';

// @desc  Login user with password
// @route /api/auth/login
// @access public
export const loginController = async (req, res) => {
    // extracting data from request body
    const { email, password } = req.body;
    // checking all the pramerets are there or not
    if (!email || !password) {
        return res.status(404).send({
            success: false,
            message: "Email and Password are mandatory"
        });
    };
    try {
        // find the user
        const user = await User.findOne({ email: email });
        if (!user) {
            return res.status(404).send({
                success: false,
                message: "User not found! Please create a new user with the same email"
            });
        };
        // check is the user is verified or not
        if (user.verifiedUser === false) {
            // if user is not verified then send him a verification email again
            const verificationMailSend = await sendAccountVerificationMail(user.email, user.verificationToken);
            console.log(verificationMailSend);
            return res.status(404).send({
                success: false,
                message: "Please verify user link sent on your account"
            });
        }
        // checking the password
        const match = await bcrypt.compare(password, user.password);
        // logging in user if password matches
        if (match) {
            const options = {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
            }
            const { accessToken, refreshToken } = await createAuthToken(user)
            return res.status(200)
                .cookie('accessToken', accessToken, options)
                .cookie('refreshToken', refreshToken, options)
                .send({
                    success: true,
                    message: "Logged in successfully",

                })
        };
        // if password is invalid
        return res.status(401).send({
            success: false,
            message: "Invalid username or password please try again with correct credentials"
        });
    } catch (error) {
        return res.status(501).send({
            success: false,
            message: error.message,
            error: error.name
        })
    }

};


// @desc  Login user with password
// @route /api/auth/signup
// @access public
export const signupController = async (req, res) => {
    // extracting data from request body
    const { name, email, password } = req.body
    // checking all the parameters are valid
    if (!name || !email || !password) {
        return res.status(401).send({
            success: false,
            message: "Name, Email and Password are mandatory"
        });
    };
    // checking if user already exists or not 
    let user = await User.findOne({ email: email });
    if (user) {
        return res.status(404).send({
            success: false,
            message: `${email} is already registered`
        });
    };
    try {
        // creating hash password
        const hashedPassword = await hashPassword(password);
        // creating a verification token
        const verificationToken = await createVerificationToken()
        // creting new user

        user = await User.create({
            name: name,
            email: email,
            verificationToken: verificationToken,
            password: hashedPassword
        });

        const verificationMailSend = await sendAccountVerificationMail(email, verificationToken);

        return res.status(200).send({
            success: true,
            message: `Verification link sent to ${email}`
        });
    } catch (error) {
        return res.status(501).send({
            success: false,
            message: error.message,
            error: error.name
        });
    }
};


// @desc verify mail
// @route /api/auth/verify
// @access public
export const verify = async (req, res) => {
    // extracting data from request body
    const token = req.params.token
    try {
        // find the user using token 
        const user = await User.findOne({ verificationToken: token });
        // check the user is exists or not
        if (!user) {
            return res.status(403).send({
                success: false,
                message: 'Invalid token please try to signup first.'
            });
        }
        // check if user is already verified or not
        if (user.verifiedUser === true) {
            return res.status(401).send({
                success: false,
                message: 'User already verified! Please login'
            });
        }
        // update the user verified status
        const userUpdate = await user.updateOne({ verifiedUser: true, verificationToken: null });
        return res.status(200).send({
            success: true,
            message: 'User verified successfully',
        })
    } catch (error) {
        return res.status(501).send({
            success: false,
            message: error.message,
            error: error.name
        });
    }
};



// @desc update user password
// @route /api/auth/changePassword
// @access private 
export const changePassword = async (req, res) => {
    const { password, newPassword, email } = req.body;
    if (!password | !newPassword | !email) {
        return res.status(500).send({
            success: false,
            message: 'Email , password, newPassword must be required'
        })
    };
    if (newPassword === password) {
        return res.status(500).send({
            success: false,
            message: 'Old password and new password must be different'
        });
    }
    const user = await User.findOne({ email: email });
    if (!user) {
        return res.status(403).send({
            success: false,
            message: "User does not exist"
        });
    };
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
        return res.status(500).send({
            success: false,
            message: 'Current password is incorrect'
        });
    };
    try {
        const hashedPassword = await hashPassword(newPassword);
        const updatePassword = await User.updateOne({ email: email }, { password: hashedPassword });
        if (updatePassword) {
            return res.status(200).send({
                success: true,
                message: 'Password Changed successfully'
            });
        }
        return res.status(500).send({
            success: false,
            message: 'Failed to update password'
        });

    } catch (error) {
        return res.status(501).send({
            success: false,
            message: error.message,
            error: error.name
        });
    };
};

// @desc request for reset user password
// @route /api/auth/forgotPassword
// @access public
export const requestForgotPassword = async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(401).send({
            success: false,
            message: 'Please enter your registered email address'
        });
    };
    try {
        const user = await User.findOne({ email: email });
        if (!user) {
            return res.status(401).send({
                success: false,
                messgae: 'Account not found with this email address'
            });
        };
        const generatedToken = await createVerificationToken();
        const storeToken = await User.updateOne({ email: email }, { verificationToken: generatedToken })
        const sendMailRequest = await sendRequestForgotPasswordMail(email, generatedToken);
        return res.status(200).send({
            success: true,
            messgae: 'sent email successfully'
        });
    } catch (error) {
        return res.status(501).send({
            success: false,
            message: error.message,
            error: error.name
        });
    }


};

// @desc reset user password with token
// @route /api/auth/forgotPassword/:token
// @access private 
export const forgotPassword = async (req, res) => {
    const token = req.params.token;
    const { newPassword } = req.body;
    try {
        const hashedPassword = await hashPassword(newPassword);
        const updateUserPassword = await User.findOneAndUpdate({ verificationToken: token }, { password: hashedPassword, verificationToken: null });
        if (updateUserPassword) {
            return res.status(200).send({
                success: true,
                message: 'Password changed successfully',
            });
        };
        return res.status(401).send({
            success: false,
            message: 'Invalid User'
        });

    } catch (error) {
        return res.status(501).send({
            success: false,
            message: error.message,
            error: error.name
        });
    }



};


// @desc get logged in user details
// @route /api/auth/getUser
// @access private 
export const getUser = async (req, res) => {
    const { id, email } = req.user;

    try {
        const userDetails = await User.findById(id).select(['-password', '-verificationToken', '-refreshToken']);
        return res.send(userDetails);
    } catch (error) {
        return res.status(501).send({
            success: false,
            message: error.message,
            error: error.name
        });
    }
};

// @desc refresh expired access token
// @route /api/auth/refreshToken
// @access private
export const refreshToken = async (req, res) => {
    const incomingRefreshToken = req.body.refreshToken
    if (!incomingRefreshToken) {
        return res.status(403).send({
            success: false,
            message: 'Refresh token is required'
        })
    }
    // return res.send(incomingRefreshToken)
    try {
        // decode the refresh token
        const decoded = await jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);

        if (!decoded) {
            return res.status(403).send({
                success: false,
                message: 'Token is invalid'
            })
        };
        // extract user and userId from the decoded token
        const { email, id } = decoded
        // retrieve user from db
        const user = await User.findById(id);
        // if user's incoming refresh token and stored token are not same, then
        if (incomingRefreshToken !== user.refreshToken) {
            return res.status(401).send({
                success: false,
                message: 'Invalid refresh token'
            })
        }
        // user incoming refresh token and stored token are same
        const options = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 1296000000
        };
        // creating new tokens and store token in db 
        const { accessToken, refreshToken } = await createAuthToken(user)
        return res.status(200)
            .cookie('accessToken', accessToken, options)
            .cookie('refreshToken', refreshToken, options)
            .send({
                success: true,
                message: "Token refreshed successfully",

            });

    } catch (error) {
        return res.status(403).send({
            success: false,
            message: error.message,
            error: error.name
        })
    }
};


// @desc logout user
// @route /api/auth/logout
// @access private
export const logout = async (req, res) => {
    const { id, email } = req.user
    try {
        await User.findOneAndUpdate({ _id: id }, { refreshToken: null });
        return res.status(200)
        .clearCookie('accessToken')
        .clearCookie('refreshToken')
        .send({
            success: true,
            message: "User logged out successfully"
        });
    } catch (error) {
        return res.status(403).send({
            success: false,
            message: error.message,
            error: error.name
        })
    }


};


