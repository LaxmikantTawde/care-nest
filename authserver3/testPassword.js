const bcrypt = require('bcrypt');

const candidatePassword = '123789'; 
const storedHash = '$2b$10$grynYHE1vfYcsTqZjuvHZ.Qs/HI9/Ik2FFAccwmJha/m7YTcDbsTi'; 

bcrypt.compare(candidatePassword, storedHash, (err, isMatch) => {
  if (err) throw err;
  console.log("Does the password match?", isMatch); 
});
