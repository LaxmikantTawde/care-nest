const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const app = express();
const PORT = 5000;
const { mogourl } = require('./config'); // Assuming you have config.js with mogourl and other settings
const cors = require('cors');
app.use(cors());

require('./models/Baby');
require('./models/Parent');

const requireToken = require('./middleware/requireToken');
const authRoutes = require('./routes/authRoutes');

// Middleware to parse JSON and URL-encoded data
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session configuration
app.use(
  session({
    secret: 'Your session secret', // Your session secret
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: false, // Set to true in production with HTTPS
      maxAge: 1000 * 60 * 60, // 1 hour
    },
  })
);

// Use routes
app.use(authRoutes);

// MongoDB connection
mongoose.connect(mogourl, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

// Test route
app.get('/', requireToken, (req, res) => {
  res.send('Your email is ' + req.user.email);
});

// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
