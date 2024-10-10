# Auth Backend

This repository contains the backend code for a user authentication system built with **MongoDB**, **Express.js**, and **Node.js**. The project includes various features such as user login, signup, email verification, password reset, and token management (JWT).

## Features

- User Signup
- Email Verification
- User Login with JWT Access and Refresh Tokens
- Password Reset & Change Password
- Refresh Token Rotation
- Secure Routes with JWT Authentication

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/vipindagar7/auth-backend.git
   cd auth-backend
   ```
2. Install dependencies:

   ```bash
   npm install
   ```
3. Create a `.env` file in the root directory and configure it as follows:

   ```bash
   NODE_ENV=development
   PORT=4000
   DB_URL=<your_mongodb_url>
   ACCESS_TOKEN_SECRET=<your_access_token_secret>
   REFRESH_TOKEN_SECRET=<your_refresh_token_secret>
   EMAIL=<your_email>
   EMAIL_PASSWORD=<your_email_password>
   ```
4. Run the application:

   ```bash
   npm run dev
   ```

## API Endpoints

For detailed routes and requests, refer to the [API Routes](./auth-api-routes.md).

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
