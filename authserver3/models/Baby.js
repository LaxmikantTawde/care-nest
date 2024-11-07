const mongoose = require('mongoose');

const babySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  age: {
    type: Number,
    required: true,
    min: 0
  },
  weight: {
    type: Number,
    required: true,
    min: 0
  },
  height: {
    type: Number,
    required: true,
    min: 0
  },
  gender: {
    type: String,
    required: true,
  },
  bmi: {
    type: Number, // BMI will be calculated and stored here
    default: 0
  }
}, { timestamps: true }); // Timestamps for createdAt and updatedAt

const Baby = mongoose.model('Baby', babySchema);

module.exports = Baby;
