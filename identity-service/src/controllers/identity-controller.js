const RefreshToken = require("../models/RefreshToken");
const User = require("../models/User");
const generateTokens = require("../utils/generateToken");
const logger = require("../utils/logger");
const { validateRegistration, validatelogin } = require("../utils/validation");
const { OAuth2Client } = require('google-auth-library');

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

//user registration
const registerUser = async (req, res) => {
  logger.info("Registration endpoint hit...");
  try {
    //validate the schema
    const { error } = validateRegistration(req.body);
    if (error) {
      logger.warn("Validation error", error.details[0].message);
      return res.status(400).json({
        success: false,
        message: error.details[0].message,
      });
    }
    const { email, password, firstName, lastName } = req.body;

    let user = await User.findOne({ email });
    if (user) {
      logger.warn("User already exists");
      return res.status(400).json({
        success: false,
        message: "User already exists",
      });
    }

    user = new User({ firstName, lastName, email, password });
    await user.save();
    logger.info("User saved successfully", user._id);

    const { accessToken, refreshToken } = await generateTokens(user);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,  // Ensures the cookie is not accessible by JavaScript
      secure: process.env.NODE_ENV === 'production',  // Only set cookie over HTTPS in production
      sameSite: 'Lax',  // Prevents cross-site request forgery (CSRF)
      maxAge: 60 * 60 * 24 * 7 * 1000,  // Optional: Set cookie expiration (1 week)
      path: '/',  // Ensure the cookie is sent with every request to your domain
    });

    return res.status(201).json({
      success: true,
      message: "User registered successfully!",
      accessToken,
      refreshToken,
    });
  } catch (e) {
    logger.error("Registration error occurred", e);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

const loginWithGoogleAuth = async (req, res) => {
  logger.info("Google login endpoint hit...");
  try {
    const { token } = req.body;
    
    if (!token) {
      logger.warn("No Google token provided");
      return res.status(400).json({
        success: false,
        message: "Google token is required"
      });
    }

    // Verify the Google token
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    
    // Check if user exists with this email
    let user = await User.findOne({ email: payload.email });
    
    if (!user) {
      // Create new user if doesn't exist
      user = new User({
        email: payload.email,
        firstName: payload.given_name,
        lastName: payload.family_name,
        password: `google_${payload.sub}`,  // Create a unique password using Google ID
        picture: payload.picture,
        googleId: payload.sub,
        isEmailVerified: payload.email_verified, // Add this field to indicate authentication method
      });
      await user.save();
      logger.info("New Google user created", user._id);
    }

    const { accessToken, refreshToken } = await generateTokens(user);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Lax',
      maxAge: 60 * 60 * 24 * 7 * 1000,
      path: '/',
    });

    return res.json({
      success: true,
      accessToken,
      refreshToken,
      userId: user._id,
    });

  } catch (e) {
    logger.error("Google login error occurred", e);
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
};

//user login
const loginUser = async (req, res) => {
  logger.info("Login endpoint hit...");
  try {
    const { error } = validatelogin(req.body);
    if (error) {
      logger.warn("Validation error", error.details[0].message);
      return res.status(400).json({
        success: false,
        message: error.details[0].message,
      });
    }
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      logger.warn("Invalid user");
      return res.status(400).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // user valid password or not
    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      logger.warn("Invalid password");
      return res.status(400).json({
        success: false,
        message: "Invalid password",
      });
    }

    const { accessToken, refreshToken } = await generateTokens(user);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,  // Ensures the cookie is not accessible by JavaScript
      secure: process.env.NODE_ENV === 'production',  // Only set cookie over HTTPS in production
      sameSite: 'Lax',  // Prevents cross-site request forgery (CSRF)
      maxAge: 60 * 60 * 24 * 7 * 1000,  // Optional: Set cookie expiration (1 week)
      path: '/',  // Ensure the cookie is sent with every request to your domain
    });

    return res.json({
      accessToken,
      refreshToken,
      userId: user._id,
    });
    
  } catch (e) {
    logger.error("Login error occured", e);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

//refresh token
const refreshTokenUser = async (req, res) => {
  logger.info("Refresh token endpoint hit...");
  try {
    const { refreshToken } = req.cookies.refreshToken;
    if (!refreshToken) {
      logger.warn("Refresh token missing");
      return res.status(400).json({
        success: false,
        message: "Refresh token missing",
      });
    }

    const storedToken = await RefreshToken.findOne({ token: refreshToken });

    if (!storedToken || storedToken.expiresAt < new Date()) {
      logger.warn("Invalid or expired refresh token");

      return res.status(401).json({
        success: false,
        message: `Invalid or expired refresh token`,
      });
    }

    const user = await User.findById(storedToken.user);

    if (!user) {
      logger.warn("User not found");

      return res.status(401).json({
        success: false,
        message: `User not found`,
      });
    }

    const { accessToken: newAccessToken, refreshToken: newRefreshToken } =
      await generateTokens(user);

    //delete the old refresh token
    await RefreshToken.deleteOne({ _id: storedToken._id });

    res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (e) {
    logger.error("Refresh token error occured", e);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

//logout

const logoutUser = async (req, res) => {
  logger.info("Logout endpoint hit...");
  try {
    const { refreshToken } = req.cookies;
    if (!refreshToken) {
      logger.warn("Refresh token missing");
      return res.status(400).json({
        success: false,
        message: "Refresh token missing",
      });
    }

    await RefreshToken.deleteOne({ token: refreshToken });
    logger.info("Refresh token deleted for logout");

    // Clear the refresh token cookie
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Lax',
      path: '/',
      domain: 'localhost'
    });

    res.json({
      success: true,
      message: "Logged out successfully!",
    });
  } catch (e) {
    logger.error("Error while logging out", e);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

module.exports = { registerUser, loginUser, refreshTokenUser, logoutUser, loginWithGoogleAuth };
