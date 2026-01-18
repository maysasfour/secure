const User = require('../models/User');
const { generateToken } = require('../utils/token');

// @desc    Register User
// @route   POST /api/v1/auth/register
exports.register = async (req, res) => {
  try {
    const { name, email, password, nationalId, role } = req.body;

    // Create user (Encryption and Hashing happen automatically via the Model)
    const user = await User.create({
      name,
      email,
      password,
      nationalId,
      role
    });

    const token = generateToken(user._id, user.role);

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        role: user.role
      }
    });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
};