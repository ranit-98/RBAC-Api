const express = require('express');
const path = require('path');
const session = require('express-session');
const flash = require('connect-flash');
const cookieParser = require('cookie-parser');

const configureCors = require('./App/config/corsConfig');
const app = express();

// -----------------------------
// CORS Setup - Allow Frontend Origin
// -----------------------------
app.use(configureCors());



// -----------------------------
// Middleware Setup
// -----------------------------
app.use(session({
  secret: 'employee-management-secret',
  resave: false,
  saveUninitialized: true
}));

app.use(cookieParser());
app.use(flash());
// Serve static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Body parsers
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Flash message middleware
app.use((req, res, next) => {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  next();
});

// -----------------------------
// Routes
// -----------------------------
const rbacRoutes = require('./App/routes/rbacRoutes');

app.use('/', rbacRoutes); 

// -----------------------------
// 404 Fallback Route
// -----------------------------
app.use((req, res) => {
  res.status(404).send('404 Not Found');
});

module.exports = app;
