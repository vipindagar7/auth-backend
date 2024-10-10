import mongoose from "mongoose";
import dotenv from 'dotenv'
dotenv.config()
const mongoURI = process.env.DB_URL


// creating a funciton which connect to MongoDB 
const connectToMongo = () => {
    mongoose.connect(mongoURI)
        .then(val => { console.log('connected to Mongoose') })
        .catch(err => { console.log('error connecting to Mongoose') })
        ;

}

export default connectToMongo;

