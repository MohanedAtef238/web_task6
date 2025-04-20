const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.use(express.json());

// In a real application, you would use a database
// This is just for demonstration purposes
const users = [];

// Secret key for JWT (in a real app, this would be in .env file)
const JWT_SECRET = process.env.jwt_secret;
const PORT = process.env.port;
// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') { // documentation says this is the name thrown when a token expires https://github.com/auth0/node-jsonwebtoken?tab=readme-ov-file#tokenexpirederror
            res.status(401).json({ message: 'token expired' });
        }
        res.status(400).json({ message: 'Invalid token' });
    }

};
// Middleware for rate limiting from https://www.npmjs.com/package/express-rate-limit , i've already made another one for my arch project so i thought i'd use this one instead of my own to compare them :D
const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	limit: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes).
	standardHeaders: 'draft-8', // draft-6: `RateLimit-*` headers; draft-7 & draft-8: combined `RateLimit` header
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers.
})

// Middleware for role-based authorization
const authorize = (role) => { // made this expect some form of grouped data and check using includes so we can check for moderator and admins in that one gateway
    return (req, res, next) => {
        if ( !role.includes(req.user.role)) {
            return res.status(403).json({ message: 'Access denied. Insufficient privileges.' });
        }
        next();
    };
};

app.use(limiter);
// Registration endpoint
app.post('/api/register', async (req, res) => {
    try {
        const { username, email ,password, role } = req.body;

        // Validate input
        if (!username || !password || !email || !role) {
            return res.status(400).json({ message: 'please fill all the required fields, username, password, email, role. roles are user, admin, moderator' });
        }
        //email validation :D 
        if (!email.includes('@') || !email.endsWith('.com')) {
            return res.status(400).json({ message: 'Email must include "@" and end with ".com" tsk tsk tsk' });
        }
        // Password validation checks for length and characters
        if ( password.length < 8 ||(!password.includes('#') && !password.includes('@') && !password.includes('!'))) {
            return res.status(400).json({message: 'Password must be at least 8 characters long and include at least one special character (!, @, or #)'});
        }
        // after thinking of an approach i decided to go with this, i am aware i could use regex but i didnt understand the syntax for numerical checking thoroughly enough to justify using it
        let hasNumber = false; // setting up bool as false initally 
        const chars = password.split(''); // splitting the password into individual characters
        for (let i = 0; i < chars.length; i++) { // we loop through the characters and look for at least one number
          const char = chars[i];
          if (!isNaN(char) && char !== ' ') { // checking if a value is a number not an empty space, passwords may not contain empty spaces to begin with
            hasNumber = true;
            break; // stop the loop once we find a number
          }
        }
        if (!hasNumber) {
            return res.status(400).json({ message: 'Password must contain at least one number.' });
        }
        // Check if user already exists
        if (users.find(u => u.username === username)) {
            return res.status(400).json({ message: 'User already exists' });
        }
        if (users.find(u => u.email === email)) {
            return res.status(400).json({ message: 'email already exists' });
        }
        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        // Create new user
        const user = {
                id: users.length + 1,
                username,
                email,
                password: hashedPassword,
                role: role || 'user' // Default role
            };
        users.push(user);
        res.status(201).json({ message: `User created successfully with role ${role}` });
    } catch (error) {
        res.status(500).json({ message: 'Error creating user' });
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find user
        const user = users.find(u => u.username === username);
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        // Validate password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ message: 'Invalid password' });
        }

        // Create and assign token
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in' });
    }
});

// Protected route example - requires authentication
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});
//Moderator for admin and moderator
app.get('/api/moderator', authenticateToken, authorize(['admin', 'moderator']), (req, res) => {
    res.json({ message: 'Admin route', adminData: 'Secret admin data' });
});
// Admin-only route example
app.get('/api/admin', authenticateToken, authorize(['admin']), (req, res) => {
    res.json({ message: 'Admin route', adminData: 'Secret admin data' });
});

// Public route example
app.get('/api/public', (req, res) => {
    res.json({ message: 'This is a public route' });
});

app.get('/api/profile', authenticateToken, (req, res) => {
    const { username, email, role } = req.user;
    res.json({
        username,
        email,
        role
      });
})

app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
      const { email, password } = req.body;
      if (!email && !password) {
        return res.status(400).json({ message: 'Please provide an email or password to update.' });
      }
      //getting a user from their sent jwt
      const userIdFromToken = req.user.id;
      //the find function returns something like a pseudo pointer from what i understand so when i do something like user.password = abcd it will actually update the user in the array, i am not sure if this is the best way to do this but it was already used in the code and i didnt do further research.
      const user = users.find(u => u.id === userIdFromToken); // syntax for finding a user from the token, i could have used the username but i thought this was more secure and less prone to impersonation 😱😱 
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      if (email) {
        if (!email.includes('@') || !email.endsWith('.com')) { // copy pasted from my implementation above
            return res.status(400).json({ message: 'Email must include "@" and end with ".com" tsk tsk tsk' });
        }
        if (users.find(u => u.email === email && u.id !== user.id)) { // makig sure we dont have users with the same email, since email providers dont allow this anyway :3
            return res.status(400).json({ message: 'email already exists' });
        }
  
        user.email = email;
      }
  
      // Password validation and update if provided
      if (password) {
        if (password.length < 8 || (!password.includes('#') && !password.includes('@') && !password.includes('!'))) {
          return res.status(400).json({ message: 'Password must be at least 8 characters and include a special character (!, @, or #)' });
        }
  
        let hasNumber = false;
        for (let i = 0; i < password.length; i++) {
          if (!isNaN(password[i]) && password[i] !== ' ') {
            hasNumber = true;
            break;
          }
        }
        if (!hasNumber) {
          return res.status(400).json({ message: 'Password must contain at least one number.' });
        }
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
      }
      res.json({ message: 'Profile updated successfully.' });
    } catch (error) {
      res.status(500).json({ message: 'Error updating profile.' });
    }
  });
  

  app.put('/api/users/:id/role', authenticateToken, authorize(['admin']), (req, res) => {
    const userId = parseInt(req.params.id); // Get the ID from the URL
    const { role } = req.body; // Expected to receive { "role": "moderator" }
    if (!role) {
      return res.status(400).json({ message: 'give me a role to update ya 7ag/7aga 🐀' });
    }
    if (role !== 'admin' && role !== 'moderator' && role !== 'user') {
      return res.status(400).json({ message: "invalid role" });
    }
    const user = users.find(u => u.id === userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }
    user.role = role;
    res.json({ message: 'User role updated to successfully.' });
  });
  

  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log('Available endpoints:');
    console.log('POST /api/register - Register a new user');
    console.log('POST /api/login - Login and get JWT token');
    console.log('GET /api/profile - Get current user profile');
    console.log('PUT /api/profile - Update current user email or password');
    console.log('PUT /api/users/:id/role - Admin only: update another user\'s role');
    console.log('GET /api/protected - Protected route (requires authentication)');
    console.log('GET /api/admin - Admin only route');
    console.log('GET /api/moderator - Admin and moderator route');
    console.log('GET /api/public - Public route');
});
