import express from 'express';
import dotenv from 'dotenv'
dotenv.config()
import cors from 'cors'
// importing database conneciton file 
import connectToMongo from './db.js';


// importing routes files 
import userRoutes from './routes/userRoutes.js';

// getting port from env file
const PORT = process.env.PORT
// creating a new express instance in a constant variable CALLED app
const app = express();

// create a connection to MongoDB
connectToMongo()

// middlewares 
app.use(cors())
app.use(express.json())


// routes
app.use('/api/auth', userRoutes)


app.listen(PORT, () => {
    console.log('listening on port ', PORT);
});