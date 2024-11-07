const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const parentSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    mobileNo: {
      type: Number,
      required: true,
      match: /^\d{10}$/,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      match: /.+\@.+\..+/,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    babyId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Baby',
      required: true,
    },
    resetPasswordToken: {
      type: String,
      default: null,
    },
    resetPasswordExpires: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);


parentSchema.pre('save', function (next) {
  const user = this;
  if (!user.isModified('password')) {
    return next();
  }
  bcrypt.genSalt(10, (err, salt) => {
    if (err) {
      return next(err);
    }
    bcrypt.hash(user.password, salt, (err, hash) => {
      if (err) {
        return next(err);
      }
      user.password = hash;
      next();
    });
  });
});


parentSchema.methods.comparePassword = function (candidatePassword) {
  const user = this;
  return new Promise((resolve, reject) => {
    console.log("Candidate Password:", candidatePassword); 
    console.log("Stored Hashed Password:", user.password);
    
    bcrypt.compare(candidatePassword, user.password, (err, isMatch) => {
      if (err) return reject(err);
      if (!isMatch) return reject(new Error('Password does not match'));
      resolve(true);
    });
  });
};

const Parent = mongoose.model('Parent', parentSchema);

module.exports = Parent;
