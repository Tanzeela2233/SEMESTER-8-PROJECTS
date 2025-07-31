require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const flash = require('connect-flash');
const User = require('./models/User');

const app = express();

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected locally'))
  .catch(err => console.log('❌ MongoDB connection error:', err));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: 'supersecret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: false }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// EJS Setup
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

// Passport Local Strategy (Manual Login)
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
  try {
    const user = await User.findOne({ email });
    if (!user) return done(null, false, { message: '⚠️ User not found' });

    if (!user.password) return done(null, false, { message: '⚠️ Please log in with Google' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return done(null, false, { message: '⚠️ Incorrect password' });

    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

// Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'http://localhost:3000/auth/google/callback',
  prompt: 'select_account'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    const name = profile.displayName;
    const profilePicture = profile.photos[0].value;

    let user = await User.findOne({ email });

    if (!user) {
      user = await User.create({ googleId: profile.id, name, email, profilePicture });
    } else {
      user.googleId = profile.id;
      user.profilePicture = profilePicture;
      await user.save();
    }

    done(null, user);
  } catch (error) {
    done(error, null);
  }
}));

// Serialize and deserialize user
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// Routes
app.get('/', (req, res) => {
  res.render('index', {
    user: req.user || null,
    message: req.flash('error'),
    email: '', // Pass empty values by default to avoid "not defined" errors
    name: ''
  });
});

// Manual Signup (No Google signup prevention)
app.post('/signup', async (req, res) => {
  const { email, name, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.render('index', {
      user: null,
      message: '⚠️ Passwords do not match!',
      email,
      name
    });
  }

  try {
    let user = await User.findOne({ email });

    const hashedPassword = await bcrypt.hash(password, 10);

    if (user) {
      // If user exists and registered with Google, allow manual signup and set/override password
      user.password = hashedPassword;
      user.name = name;
      await user.save();
    } else {
      // If user doesn't exist, create a new one
      user = new User({ email, name, password: hashedPassword });
      await user.save();
    }

    req.login(user, (err) => {
      if (err) return res.render('index', { user: null, message: '⚠️ Something went wrong, please try again.', email, name });
      res.redirect('/signup-success');
    });
  } catch (error) {
    console.error(error);
    res.render('index', { user: null, message: '⚠️ Something went wrong, please try again.', email, name });
  }
});

// Manual Login
app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/',
  failureFlash: true
}));

// Google Auth Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => res.redirect('/'));

// Logout
app.get('/logout', (req, res) => {
  req.logout(() => {
    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.redirect('/');
    });
  });
});

// Signup Success Page
app.get('/signup-success', (req, res) => {
  if (!req.user) {
    return res.redirect('/'); // Redirect if no user is logged in
  }

  res.render('signup-success', {
    name: req.user.name,
    email: req.user.email
  });
});


app.listen(3000, () => console.log('🚀 Server running on http://localhost:3000'));
