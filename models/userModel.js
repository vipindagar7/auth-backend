import mongoose, { Schema, Types } from "mongoose";


// create a user schema 
const UserSchema = new Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    verifiedUser: {
        type: Boolean,
        required: true,
        default: false,
    },
    verificationToken: {
        type: String,
    },
    refreshToken: {
        type: String
    },
    timestamp: {
        type: String,
        default: new Date
    }
});

// create a model from user schema 
export const userModel = mongoose.model('user', UserSchema);
