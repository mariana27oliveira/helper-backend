const passport = require ('passport');
const {Strategy} = require('passport-google-oauth20');

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
      const userRef = await db.collection('GoogleUsers').doc(id).get();
      if (userRef.exists) {
        const userData = userRef.data(); 
        done(null, userData);
      } else {
        throw new Error("User not found");
      }
  } catch (err) {
      console.log(err);
      done(err, null);
  }
});


async function googleVerifyFunction(accessToken, refreshToken, profile, done) {
    const { id: googleId, displayName, emails } = profile;
  
    try {
        // Salvar dados na coleção GoogleUsers
        const userRef = await db.collection('GoogleUsers').doc(googleId).get();
  
        if (!userRef.exists) {
            const userData = {
                displayName: displayName, 
                email: emails[0].value, 
            };
            await db.collection('GoogleUsers').doc(googleId).set(userData);
        }
  
        // Adicionando uma mensagem de sucesso ao objeto de perfil
        profile.message = 'User logged in successfuly!';
  
        return done(null, profile);
    } catch (err) {
        console.error('Error in verifying or creating the user', err);
        return done(err, null);
    }
  }
  


passport.use(
    new Strategy({
        clientID: "871005441383-21r86rlerhcl2tnr7hdt2fo54i32kge5.apps.googleusercontent.com",
        clientSecret: "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",
        callbackURL: "https://1f69-144-64-20-16.ngrok-free.app/user/google/redirect",
        scope: ['profile', 'email'],
        prompt: 'select_account'  // Adicione esta linha
}, googleVerifyFunction)
);

module.exports = {googleVerifyFunction};