const passport = require ('passport');
const {Strategy} = require('passport-discord');

const { db } = require('../database/firebase.js'); 


passport.serializeUser((user, done) => {
  console.log('Serializing User...');
  console.log(user);
  done(null, user.id)
});

passport.deserializeUser(async (id, done) => {
  console.log('Deserializing User');
  console.log(id);
  try {
      const user = await db.collection('DiscordUsers').doc(id).get();
      if (!user) throw new Error("User not found");
      console.log (user);
      done(null, user);
  } catch (err) {
      console.log(err);
      done(err, null);
  }
});


async function discordVerifyFunction(accessToken, refreshToken, profile, done) {
    const { id: discordId, username, email } = profile;
  
    try {
      const userRef = await db.collection('DiscordUsers').doc(discordId).get();
  
      if (!userRef.exists) {
        const userData = {
          username: username,
          email: email ? email : 'N/A', // Use 'N/A' se o email for undefined
        };
        await db.collection('DiscordUsers').doc(discordId).set(userData);
      }
  
      return done(null, profile);
    } catch (err) {
      console.error('Error in verifying or creating the user', err);
      return done(err, null);
    }
  }
  


passport.use(
    new Strategy({
        clientID: "1192787193572368504",
        clientSecret: "IleItfUSTdA4jQFHHBEStdxrtrlRrLp-",
        callbackURL: "http://localhost:3000/user/discord",
        scope: ['identify'],
}, discordVerifyFunction)
);

module.exports = {discordVerifyFunction};