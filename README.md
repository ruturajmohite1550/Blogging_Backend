Problem Solving Approach:
The backend was designed to provide a secure, scalable API for handling user accounts and blog posts:
Authentication: Implemented JWT-based authentication to manage user sessions securely.
Password Security: Used bcrypt to hash and verify passwords.
Authorization: Routes are protected using a middleware that checks for a valid token.
Blog Post Management: APIs for CRUD operations on blog posts, scoped to authenticated users.
CAPTCHA Integration: Validates Google reCAPTCHA v2 tokens on signup to prevent bots from creating accounts.

ChatGPT:
  - Guided integration of Google reCAPTCHA in both frontend and backend.
  - Helped with writing secure API endpoints and validating tokens.
  - Provided suggestions for code structure and error handling.

setup instructions:
To set up the backend of your blog system, start by cloning the repository using git clone https://github.com/your-username/blog-backend.git 
and navigate into the project directory. Install all necessary dependencies with npm install. Next, create a .env file in the root of the project 
to store your environment variables securely. This file should include your server port (PORT=5000), JWT secret (JWT_SECRET=your_jwt_secret_key), 
frontend URL (FRONTEND_URL=http://localhost:3000), and your Google reCAPTCHA secret key (RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key). 
Replace the placeholder values with your actual credentials.

Ensure that your MySQL database is up and running and includes the required tables such as users and posts for handling authentication and blog data. 
After setting up your database and environment, you can start the backend server using node server.js. The server will run on http://localhost:5000
and be ready to handle API requests including those protected by reCAPTCHA for enhanced security.
