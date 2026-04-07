# Single Page App Backend

A Node.js/Express API with MongoDB, JWT authentication, and file uploads.

## Features
- User registration and login
- JWT-based authentication
- Case management (CRUD operations)
- File upload support
- MongoDB database integration

## Local Development

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create a `.env` file with:
   ```
   MONGO_URI=your_mongodb_connection_string
   JWT_SECRET=your_jwt_secret
   ```

3. Run the server:
   ```bash
   npm start
   ```

## Vercel Deployment

1. Push your code to GitHub
2. Connect your repo to Vercel
3. Set environment variables in Vercel dashboard:
   - `MONGO_URI`
   - `JWT_SECRET`
   - `NODE_ENV=production`

The app is already configured for Vercel deployment with the included `vercel.json` file.