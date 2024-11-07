const validateRegistrationData = (req, res, next) => {
    const { baby, parent } = req.body;
    if (!baby || !parent || !parent.email || !parent.phone || !baby.name || !baby.birthDate) {
      return res.status(400).json({ message: 'Missing required fields.' });
    }
    next();
  };
  
  module.exports = { validateRegistrationData };
  