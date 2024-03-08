const mongoose = require('mongoose');
const User = require('./models/user');
require('dotenv').config();
const DB=process.env.DB_URL
// Connect to MongoDB
mongoose.connect(DB, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(async () => {
    console.log("Connected to MongoDB");

    // Create admin user with username, email, and isAdmin flag
    const adminUser = new User({
      username: 'RaviBhai',
      email: 'RaviBhai@gmail.com',
      isAdmin: true,
    });

    // Use passport-local-mongoose's register method to handle hashing
    await User.register(adminUser, process.env.ADMIN_PASSWORD);

    console.log('Admin user created successfully');
    // Close the connection after saving the user
    mongoose.disconnect();
  })
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error);
  });
