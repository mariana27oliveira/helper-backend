const {Router} = require ('express');
const { FieldValue } = require('firebase-admin/firestore')
const admin = require('firebase-admin')
const { db } = require('../database/firebase.js')
const bcrypt = require('bcrypt');
const { comparePassword } = require('../utils/hashPassword.js');
const passport = require ('passport');
const discordStrategy = require('../strategies/discord.js'); 
const googleStrategy = require('../strategies/google.js');
const axios = require('axios');

const { DateTime } = require('luxon');



require('dotenv').config();

const bodyParser = require('body-parser');


const router = Router ();

router.use(bodyParser.json());


console.log(process.env.JWT_SECRET)

const jwt = require('jsonwebtoken');
const secretKey = process.env.JWT_SECRET; 

function generateAccessToken(userId) {
    return jwt.sign({ UserId: userId }, secretKey);
}


function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) return res.status(401).send({ error: 'Failed to authenticate token' });
        req.user = decoded; // Decoded object has UserId 
        next();
    });
}



/**
 * @swagger
 * components:
 *   schemas:
 *     UserData:
 *       type: object
 *       properties:
 *         Name:
 *           type: string
 *         Email:
 *           type: string
 *         Password:
 *           type: string
 *         PhoneContact:
 *           type: string
 *     VolunteerData:
 *       type: object
 *       properties:
 *         Name:
 *           type: string
 *         Email:
 *           type: string
 *         Password:
 *           type: string
 *         PhoneContact:
 *           type: string
 *         Token:
 *           tyoe: string
 *     RequestData:
 *       type: object
 *       properties:
 *         Location:
 *           type: object
 *           properties:
 *             latitude:
 *               type: number
 *             longitude:
 *               type: number
 *         Timestamp:
 *           type: string
 *           format: date-time
 *         UserID:
 *           type: string
 *         Status:
 *           type: string
 *         VolunteerID:
 *           type: string
 *     ReviewData:
 *       type: object
 *       properties:
 *         Feedback:
 *           type: string
 *         Rating:
 *           type: number
 *         UserID:
 *           type: string
 *         VolunteerID:
 *           type: string
 *         RequestID:
 *           type: string
 *     LocationVolunteer:
 *       type: object
 *       properties:
 *         Location:
 *           type: object
 *           properties:
 *             latitude:
 *               type: number
 *             longitude:
 *               type: number
 */


/**
 * @swagger
 * tags:
 *   name: Authentication
 *   description: Operations related to user authentication
 */

/**
 * @swagger
 * tags:
 *   name: Requests
 *   description: Operations related to user requests
 */

/**
 * @swagger
 * tags:
 *   name: Profile
 *   description: Operations related to user profile
 */



/**
 * @swagger
 * /user/signup:
 *   post:
 *     summary: Create a new user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               Name:
 *                 type: string
 *               Email:
 *                 type: string
 *                 format: email
 *               Password:
 *                 type: string
 *               ConfirmPassword:
 *                 type: string
 *               PhoneContact:
 *                 type: string
 *                 pattern: ^\d+$   
 *     responses:
 *       200:
 *         description: User created successfully
 *       400:
 *         description: Invalid input data
 *       500:
 *         description: Server error
 */


//SIGNUP (NAME, PASSWORD, EMAIL, PHONECONTACT)
router.post('/signup', async (req, res) => {
    try {
        const { Name, Email, Password, ConfirmPassword, PhoneContact } = req.body;
        /*if (!Name || !Email || !Password || !PhoneContact) {
            return res.status(400).send({ error: 'All fields are required.' });
        }*/

        /*if (!isValidEmail(Email)) {
            return res.status(400).send({ error: 'Invalid email format.' });
        }*/

        if (Password !== ConfirmPassword) {
            return res.status(400).send({ error: 'Passwords do not match.' });
        }
        
            const existingUserWithEmail = await db.collection('Users').where('Email', '==', Email).get();
        if (!existingUserWithEmail.empty) {
            return res.status(400).send({ error: 'Email already exists.' });
        }

        if (!isValidPhoneNumber(PhoneContact)) {
            return res.status(400).send({ error: 'Invalid phone number format.' });
        }

        const existingUserWithPhone = await db.collection('Users').where('PhoneContact', '==', PhoneContact).get();
        if (!existingUserWithPhone.empty) {
            return res.status(400).send({ error: 'Phone number already exists.' });
        }

        // Hash password before saving it in the data base
        const hashedPassword = await bcrypt.hash(Password, 10);

        
        const newUserRef = await db.collection('Users').add({
            Name: Name,
            Password: hashedPassword,
            Email: Email,
            PhoneContact: PhoneContact,
        });

        // Generates token JWT
        const jwtToken = generateAccessToken(newUserRef.id);

        res.status(200).send({ 
            message: 'User added successfully',
            UserID: newUserRef.id,
            token: jwtToken 
        });

    } catch (error) {
        console.error('Error occurred during user signup:', error);
        res.status(500).send({ error: 'Server error' });
    }
});

/*function isValidEmail(email) {
    return /\S+@\S+\.\S+/.test(email);
}*/

function isValidPhoneNumber(phone) {
    return /^\d{9}$/.test(phone);
}


router.get('/google', passport.authenticate('google'), (req, res) => {
    res.send(200);
})


router.get('/google/redirect', passport.authenticate('google'), (req, res) => {
    res.send(200);
})


/*

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));



router.get('/google/redirect', passport.authenticate('google'), (req, res) => {
    res.send(200);
})
*/


/**
 * @swagger
 * /user/add/{googleId}:
 *   patch:
 *     summary: Add phone contact 
 *     tags: [Authentication]
 *     parameters:
 *       - in: path
 *         name: googleId
 *         required: true
 *         description: The ID of the user
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               PhoneContact:
 *                 type: string
 *                 pattern: ^\d+$  
 *                 description: The new phone contact of the user
 *     responses:
 *       200:
 *         description: User phone contact added successfully
 *       400:
 *         description: Invalid user ID
 *       500:
 *         description: Server error
 */

//SAVE AND ADD INFORMATIONS
router.patch('/add/:googleId', async (req, res) => {
    try {

        const { googleId } = req.params;
        const { PhoneContact } = req.body;
        console.log('Received googleId:', googleId);
        if (!googleId) {
            return res.status(400).send({ error: 'Invalid googleId' });
        }

        // Verifies if PhoneContact already exists in 'Users' collection
        const userWithPhoneContact = await db.collection('Users')
            .where('PhoneContact', '==', PhoneContact)
            .get();

        if (!userWithPhoneContact.empty) {
            return res.status(400).send({ error: 'Phone contact already exists' });
        }

        const googleDoc = await db.collection('GoogleUsers').doc(googleId).get();

        if (!googleDoc.exists) {
            return res.status(404).send({ error: 'Google user not found' });
        }

        const googleUserData = googleDoc.data();


        if (!googleUserData.displayName || !googleUserData.email) {
            return res.status(400).send({ error: 'Incomplete Google user data' });
        }
    
        // Creates new document in "Users" collection
        await db.collection('Users').doc(googleId).set({
          name: googleUserData.displayName,
          email: googleUserData.email,
          phoneContact: PhoneContact,
        });

    
        return res.status(201).send('User created successfully');
      } catch (error) {
        console.error('Error creating user:', error);
        return res.status(500).send('Error creating user');
      }
    });
    


/**
 * @swagger
 * /user/login:
 *   post:
 *     summary: Authenticate user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               Email:
 *                 type: string
 *                 format: email
 *               Password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Authentication successful
 *       400:
 *         description: Missing credentials or invalid email/password format
 *       401:
 *         description: User not found or wrong password
 *       500:
 *         description: Server error
 */



//LOGIN (EMAIL, PASSWORD)
router.post('/login', async (req, res) => {
    try {
        const { Email, Password } = req.body;
        if (!Email || !Password) {
            return res.status(400).send({ error: 'Missing credentials' });
        }
        const user = await db.collection('Users').where('Email', '==', Email).limit(1).get();
        if (user.empty) {
            return res.status(401).send({ error: 'User not found.' });
        }
        const userData = user.docs[0].data();
        
        const passwordMatch = comparePassword(Password, userData.Password); 
        
        if (!passwordMatch) {
            return res.status(401).send({ error: 'Wrong password' });
        }

        // Generates a token JWT
        const jwtToken = generateAccessToken(user.docs[0].id);

        res.status(200).send({ 
            message: 'Authentication successful',
            token: jwtToken 
        });


    } catch (error) {
        console.error('Login failed', error);
        res.status(500).send({ error: 'Server error' });        
    }
});



const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'Gmail', // It can be other service
    auth: {
        user: 'helper.mobile.app.2024@gmail.com',
        pass: 'tgtp uvwq btrk mcad'
    }
});

// Function to sent the email
const sendEmail = async (to, subject, text) => {
    try {
        await transporter.sendMail({
            from: 'helper.mobile.app.2024@gmail.com',
            to,
            subject,
            text
        });
    } catch (error) {
        console.error('Erro ao enviar e-mail:', error);
        throw error;
    }
};


/**
 * @swagger
 * /user/forgot_password_1:
 *   post:
 *     summary: Forgot Password (1)
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               Email:
 *                 type: string
 *                 format: email
 *     responses:
 *       200:
 *         description: Email found, proceed to next step
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 userId:
 *                   type: string
 *       400:
 *         description: Email is required
 *       404:
 *         description: Email not found
 *       500:
 *         description: Server error
 */

router.post('/forgot_password_1', async (req, res) => {
    try {
        const { Email } = req.body;
        if (!Email) {
            return res.status(400).send({ error: 'Email is required' });
        }

        const userSnapshot = await db.collection('Users').where('Email', '==', Email).get();

        if (userSnapshot.empty) {
            return res.status(404).send({ error: 'Email not found' });
        }

        const userDoc = userSnapshot.docs[0];
        const userId = userDoc.id;

        // Generates a verification code
        const verificationCode = Math.floor(1000 + Math.random() * 9000); // 4 digit code
        console.log(`Generated verification code: ${verificationCode}`);

        // Stores the code in the database
        await db.collection('Users').doc(userId).update({ verificationCode });

        // Send the verification code
        await sendEmail(
            Email,
            'Password Recovery Code',
            `Your password recovery code is ${verificationCode}`
        );

        return res.status(200).send({ message: 'Email sent successfully', userId });

    } catch (error) {
        console.error('Error in forgot_password_1', error);
        return res.status(500).send({ error: 'Server error' });
    }
});


router.post('/forgot_password_2', async (req, res) => {
    try {
        const { userId, verificationCode } = req.body;
        console.log(`Verification attempt for userId: ${userId} with code: ${verificationCode}`); 
        // Verifies if the code matches the one stored in the database 
        const userDoc = await db.collection('Users').doc(userId).get();
        if (!userDoc.exists) {
            return res.status(404).send({ error: 'User not found' });
        }

        const userData = userDoc.data();
        console.log(`Stored verification code: ${userData.verificationCode}, Provided code: ${verificationCode}`); 
        if (userData.verificationCode != verificationCode) {
            return res.status(400).send({ error: 'Invalid verification code' });
        }

        // If the code is valid, the code stored in the database is deleted 
        await db.collection('Users').doc(userId).update({ verificationCode: null });

        return res.status(200).send({ message: 'Verification code valid' });

    } catch (error) {
        console.error('Error in forgot_password_2', error);
        return res.status(500).send({ error: 'Server error' });
    }
});

/**
 * @swagger
 * /user/forgot_password_3/{userId}:
 *   post:
 *     summary: Forgot Password (3)
 *     tags: [Authentication]
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         description: The ID of the user to update
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               newPassword:
 *                 type: string
 *               confirmNewPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: Password updated successfully
 *       400:
 *         description: Bad request (e.g., passwords do not match, missing parameters)
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */

const comparePasswords = (password1, password2) => password1 === password2;

router.post('/forgot_password_3/:userId', async (req, res) => {
    try {
        const { userId } = req.params; 
        const { newPassword, confirmNewPassword } = req.body; 
        console.log(`Received userId: ${userId}`);

        if (!newPassword || !confirmNewPassword) {
            return res.status(400).send({ error: 'All fields are required' });
        }

        if (!comparePasswords(newPassword, confirmNewPassword)) {
            return res.status(400).send({ error: 'Passwords do not match' });
        }

        const userDoc = await db.collection('Users').doc(userId).get();

        if (!userDoc.exists) {
            return res.status(404).send({ error: 'User not found' });
        }

        const userData = userDoc.data();
        const hashedPassword = userData.Password; 


        const passwordMatch = await bcrypt.compare(newPassword, hashedPassword);
        if (passwordMatch) {
            return res.status(400).send({ error: 'New password cannot be the same as the old password' });
        }

        const newHashedPassword = await bcrypt.hash(newPassword, 10);

        await db.collection('Users').doc(userId).update({ Password: newHashedPassword });

        return res.status(200).send({ message: 'Password updated successfully' });

    } catch (error) {
        console.error('Error in forgot_password_3', error);
        return res.status(500).send({ error: 'Server error' });
    }
});



/**
 * @swagger
 * /user/newRequest:
 *   post:
 *     summary: New Request
 *     tags: [Requests]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               UserID:
 *                 type: string
 *               Timestamp:
 *                 type: string
 *                 format: date-time
 *               Location:
 *                 type: object
 *                 properties:
 *                   latitude:
 *                     type: number
 *                   longitude:
 *                     type: number
 *               VolunteerID:
 *                 type: string
 *     responses:
 *       200:
 *         description: Request added successfuly
 *       500:
 *         description: Server error
 */

function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371; 
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
      Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    const distance = R * c;
    return distance;
  }
  

//CREATE NEW REQUEST 
router.post('/newRequest', authenticateToken, async (req, res) => {
    try {

        console.log('Request received for new request creation');

        const { Timestamp, Status, Location, Volunteers , VolunteerID, Duration, VolunteerPoints } = req.body;
        const requestLocation = new admin.firestore.GeoPoint(Location.latitude, Location.longitude);
        const timestamp = admin.firestore.FieldValue.serverTimestamp();
        const status = "pendent"; 

        const UserID = req.user.UserId;

        console.log('Decoded UserID from token:', UserID);

        // Updates the location of each volunteer that is logged in
        for (const volunteer of Volunteers) {
            const volunteerID = volunteer.id;
            const volunteerLocation = new admin.firestore.GeoPoint(volunteer.Location.latitude, volunteer.Location.longitude);
            await db.collection('LocationVolunteers').doc(volunteerID).set({
                Location: volunteerLocation
            }, { merge: true });
        }

        // Verifies if the user has already a pending or ongoing request
        const pendingRequest = await db.collection('Requests')
            .where('UserID', '==', UserID)
            .where('Status', 'in', ['pendent', 'accepted']) // This handles the 'OR' condition
            .get();

        if (!pendingRequest.empty) {
            return res.status(400).send({ error: 'User already has a pending or ongoing request.' });
        }

        // Searches volunteer locations 
        const volunteersSnapshot = await db.collection('LocationVolunteers').get();
        const nearbyVolunteers = [];
        const registrationTokens = [];  // List of FCM tokens of nearby volunteers

        // Await for all asynchronous operations inside the forEach
        await Promise.all(volunteersSnapshot.docs.map(async (doc) => {
            const volunteerLocation = doc.data().Location;
            const distance = calculateDistance(requestLocation.latitude, requestLocation.longitude, volunteerLocation.latitude, volunteerLocation.longitude);
            if (distance <= 1) { // If the distance is inferior to 1 km
                nearbyVolunteers.push(doc.id); // Adds volunteer id to the list 

                // Gets the FCM token of the volunteer
                const volunteerDoc = await db.collection('Volunteers').doc(doc.id).get();
                if (volunteerDoc.exists) {
                    const volunteerData = volunteerDoc.data();
                    if (volunteerData.fcmToken) {
                        registrationTokens.push(volunteerData.fcmToken);
                    }
                }
            }
        }));

        console.log('Nearby volunteers:', nearbyVolunteers);

        const RequestRef = await db.collection('Requests').add({
            UserID: UserID,
            Timestamp: timestamp,
            Status: status,
            Location: requestLocation,
            VolunteerID: VolunteerID,
            Duration: 0,
            VolunteerPoints: 0
        });
        
        console.log('Request added successfully with ID:', RequestRef.id);
        console.log('Registration tokens:', registrationTokens);

        // Sends notification to nearby volunteers 
        if (registrationTokens.length > 0) {
            const notificationPayload = {
                notification: {
                    title: 'New Help Request',
                    body: 'A new call for help was triggered nearby'
                }
            };
            await admin.messaging().sendEachForMulticast({ tokens: registrationTokens, ...notificationPayload });
            console.log('Notification sent to nearby volunteers.');
        } else {
            console.log('No nearby volunteers with valid FCM tokens found.');
        }
        
        res.status(200).send({ message: 'Request added successfully.', requestId: RequestRef.id, nearbyVolunteers });
    } catch (error) {
        console.error('Request not added', error);
        res.status(500).send({ error: 'Server error' });
    }
})



/**
 * @swagger
 * /user/requests/{userId}:
 *   get:
 *     summary: Get request information
 *     tags: [Requests]
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         description: The ID of the user to retrieve the request for
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Request information retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 RequestID:
 *                   type: string
 *                   description: The ID of the request
 *                 Location:
 *                   type: string
 *                   description: The address of the request location
 *                 Status:
 *                   type: string
 *                   description: The status of the request
 *                 Timestamp:
 *                   type: string
 *                   format: date-time
 *                   description: The timestamp of when the request was made
 *                 VolunteerName:
 *                   type: string
 *                   description: The name of the volunteer assigned to the request
 *                 VolunteerPhoneContact:
 *                   type: string
 *                   description: The phone contact of the volunteer
 *       400:
 *         description: Invalid user ID
 *       404:
 *         description: Request not found
 *       500:
 *         description: Server error
 */

// SEE REQUEST INFORMATION (TIMESTAMP, STATUS, LOCATION, VOLUNTEER NAME and CONTACT) - OpenStreetMap Nominatim API
//router.get('/requests/:userId', async (req, res) => {
router.get('/requests', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.UserId;
        //const userId = req.params.userId;
        if (!userId) {
            return res.status(400).send({ error: 'Invalid userId' });
        }

        // Find the request by UserID and status 'accepted'
        const requestsSnapshot = await db.collection('Requests')
            .where('UserID', '==', userId)
            .where('Status', 'in', ['accepted', 'completed']) // This handles the 'OR' condition
            .limit(1) // Assuming only one request per user with status 'accepted'
            .get();

        if (requestsSnapshot.empty) {
            return res.status(404).send({ error: 'Request not found' });
        }

        const request = requestsSnapshot.docs[0];
        const requestData = request.data();
        const { Location, Status, Timestamp, VolunteerID } = requestData;

        let volunteerName = '';
        let volunteerPhoneContact = '';
        if (VolunteerID) {
            const volunteerRef = await db.collection('Volunteers').doc(VolunteerID);
            const volunteer = await volunteerRef.get();
            if (volunteer.exists) {
                const volunteerData = volunteer.data();
                volunteerName = volunteerData.Name || 'Unknown';
                volunteerPhoneContact = volunteerData.PhoneContact || 'Unknown';
            }
        }
        
        const response = await axios.get(`https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${Location.latitude}&lon=${Location.longitude}`, {
            headers: {
              'User-Agent': 'Helper (helper.mobile.app.2024@gmail.com)' 
            }
          });         
        if (response.data) {
            const address = response.data.display_name;
            const formattedTimestamp = DateTime.fromMillis(requestData.Timestamp._seconds * 1000).setZone('Europe/Lisbon').toFormat('EEE, dd MMM yyyy HH:mm:ss');
            const responseData = {
                RequestID: request.id, // Adding the RequestID
                Location: address,
                Status: Status,
                Timestamp: formattedTimestamp,
                VolunteerName: volunteerName,
                VolunteerPhoneContact: volunteerPhoneContact
            };
            return res.status(200).send(responseData);
        } else {
            return res.status(500).send({ error: 'Failed to retrieve address' });
        }
    } catch (error) {
        console.error('Error in finding request', error);
        res.status(500).send({ error: 'Server error' });
    }
});


/**
 * @swagger
 * /user/updateRequest/{requestId}:
 *   patch:
 *     summary: Update request status 
 *     tags: [Requests]
 *     parameters:
 *       - in: path
 *         name: requestId
 *         required: true
 *         description: The ID of the request to update
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               Status:
 *                 type: string
 *                 description: The new status of the request
 *     responses:
 *       200:
 *         description: Request updated successfully
 *       400:
 *         description: Invalid request ID
 *       500:
 *         description: Server error
 */


// UPDATE REQUEST STATUS (AFTER CREATING OR FINISHING REQUEST)
router.patch('/updateRequest/:requestId', async (req, res) => {
    try {
        const requestId = req.params.requestId;
        if (!requestId) {
            return res.status(400).send({ error: 'Invalid requestId' });
        }

        const { Status } = req.body;
        const updateFields = {};

        if (Status) {
            updateFields.Status = Status;
            if (Status === 'finished') {
                updateFields.finishedTime = new Date(); // Add finishedTime field with current timestamp
            }
        }

        if (Status === "completed") {
            const requestDoc = await db.collection('Requests').doc(requestId).get();
            if (requestDoc.exists) {
                const requestData = requestDoc.data();
                if (requestData.Status === "completed") {
                    updateFields.Status = "finished";
                    updateFields.finishedTime = new Date(); // Ensure finishedTime is updated if completed
                }
            }
        }

        const requestRef = db.collection('Requests').doc(requestId);
        await requestRef.update(updateFields);


        // Verifies if finishedTime was added and calculates the duration (if necessary)
        if (updateFields.finishedTime) {
            const requestDoc = await requestRef.get(); 
            const requestData = requestDoc.data();
            const acceptedTime = requestData.acceptedTime.toDate(); 
            const finishedTime = requestData.finishedTime.toDate(); 
            
            // Calculates the difference between acceptedTime and finishedTime
            const diffMs = finishedTime - acceptedTime; 
            const diffMinutes = Math.round(diffMs / 60000); //Converts to minutes

            // Duration in hours and minutes
            const hours = Math.floor(diffMinutes / 60);
            const minutes = diffMinutes % 60;
            const formattedDuration = hours > 0 
                ? `${hours}h ${minutes}m` 
                : `${minutes}m`;

            // Updates duration field
            await requestRef.update({ Duration: formattedDuration });
            console.log('Duration calculated as:', formattedDuration);
        }

        res.status(200).send({ message: 'Request updated successfully' });
    } catch (error) {
        console.error('Error in updating request', error);
        res.status(500).send({ error: 'Server error' });
    }
});


/**
 * @swagger
 * /user/review/{userId}:
 *   post:
 *     summary: Create a review for the most recent request of a user
 *     tags: [Requests]
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         description: The ID of the user submitting the review
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               Feedback:
 *                 type: string
 *                 description: Feedback provided by the user
 *               Rating:
 *                 type: number
 *                 description: Rating given by the user (e.g., from 1 to 10)
 *             required:
 *               - Feedback
 *               - Rating
 *     responses:
 *       200:
 *         description: Review added successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Review added successfully.
 *                 RequestID:
 *                   type: string
 *                   description: The ID of the request that was reviewed
 *       400:
 *         description: Bad request, missing or invalid parameters
 *       404:
 *         description: No requests found for this user
 *       500:
 *         description: Server error
 */


// CREATE VOLUNTEER REVIEW BASED ON MOST RECENT USER REQUEST
//router.post('/review/:userId', async (req, res) => {
router.post('/review', authenticateToken, async (req, res) => {
    try {
        //const { userId } = req.params;
        const userId = req.user.UserId;
        const { Feedback, Rating } = req.body;

        if (!userId) {
            return res.status(400).send({ error: 'UserID is required' });
        }

        if (!Feedback || typeof Rating !== 'number') {
            return res.status(400).send({ error: 'Feedback and Rating are required' });
        }

        // Searches for the most recent request made by the user
        const requestsSnapshot = await db.collection('Requests')
            .where('UserID', '==', userId)
            .orderBy('Timestamp', 'desc')
            .limit(1)
            .get();

        if (requestsSnapshot.empty) {
            return res.status(404).send({ error: 'No requests found for this user' });
        }

        const recentRequest = requestsSnapshot.docs[0];
        const requestData = recentRequest.data();
        const { VolunteerID } = requestData;
        const RequestID = recentRequest.id;

        // Check if a review already exists for this request
        const reviewSnapshot = await db.collection('Reviews').doc(RequestID).get();

        if (reviewSnapshot.exists) {
            return res.status(400).send({ error: 'A review for this request has already been submitted.' });
        }

        // Creates the document in the Reviews collection with the request id as id 
        const VolunteerReviewRef = db.collection('Reviews').doc(RequestID);
        await VolunteerReviewRef.set({
            Feedback,
            Rating,
            UserID: userId,
            VolunteerID,
            RequestID
        });

        res.status(200).send({ message: 'Review added successfully.', RequestID });
    } catch (error) {
        console.error('Review not added', error);
        res.status(500).send({ error: 'Server error' });
    }
});



/**
 * @swagger
 * /user/finished_request/{requestId}:
 *   get:
 *     summary: Get finished request details and review information
 *     tags: [Requests]
 *     parameters:
 *       - in: path
 *         name: requestId
 *         required: true
 *         description: The ID of the request to fetch details for
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Request details and review retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 Timestamp:
 *                   type: string
 *                   description: The timestamp of when the request was made
 *                 Status:
 *                   type: string
 *                   description: The status of the request
 *                 AcceptedTime:
 *                   type: string
 *                   description: The time when the request was accepted
 *                 FinishedTime:
 *                   type: string
 *                   description: The time when the request was finished
 *                 Duration:
 *                   type: string
 *                   description: The total duration of the request
 *                 Location:
 *                   type: string
 *                   description: The address of the request location
 *                 VolunteerName:
 *                   type: string
 *                   description: The name of the volunteer who received the review
 *                 Review:
 *                   type: object
 *                   description: The review details for the request (if available)
 *                   properties:
 *                     Feedback:
 *                       type: string
 *                       description: The feedback given by the user
 *                     Rating:
 *                       type: number
 *                       description: The rating given by the user (1-5)
 *       400:
 *         description: Invalid request or request is not in a finished state
 *       404:
 *         description: Request not found
 *       500:
 *         description: Server error
 */

// GET FINISHED REQUEST DETAILS AND REVIEW
router.get('/finished_request/:requestId', async (req, res) => {
    try {
        const requestId = req.params.requestId;

        // Fetch the request data by ID
        const requestSnapshot = await db.collection('Requests').doc(requestId).get();

        if (!requestSnapshot.exists) {
            return res.status(404).send({ error: 'Request not found' });
        }

        const requestData = requestSnapshot.data();
        
        // Check if the status is 'completed' or 'finished'
        if (requestData.Status === 'completed') {
            return res.status(200).send({ message: 'Waiting for the volunteer to finish the request' });
        }

        if (requestData.Status !== 'finished') {
            return res.status(400).send({ error: 'Request is not in a finished state' });
        }

        // Use luxon to format the date to Portugal time zone (Europe/Lisbon)
        const timestamp = DateTime.fromMillis(requestData.Timestamp._seconds * 1000).setZone('Europe/Lisbon').toFormat('EEE, dd MMM yyyy HH:mm:ss');
        const acceptedTime = requestData.acceptedTime ? DateTime.fromMillis(requestData.acceptedTime._seconds * 1000).setZone('Europe/Lisbon').toFormat('EEE, dd MMM yyyy HH:mm:ss') : 'N/A';
        const finishedTime = requestData.finishedTime ? DateTime.fromMillis(requestData.finishedTime._seconds * 1000).setZone('Europe/Lisbon').toFormat('EEE, dd MMM yyyy HH:mm:ss') : 'N/A';
        const duration = requestData.Duration || 'N/A';

        // Convert location coordinates to an address using the Nominatim API
        const { latitude, longitude } = requestData.Location;
        let address = 'Unknown location';
        try {
            const response = await axios.get(`https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${latitude}&lon=${longitude}`, {
                headers: {
                  'User-Agent': 'Helper (helper.mobile.app.2024@gmail.com)' 
                }
              });               
              if (response.data && response.data.display_name) {
                address = response.data.display_name;
            }
        } catch (error) {
            console.error('Error fetching address from Nominatim API:', error.message);
        }

        // Fetch the volunteername from the Volunteers collection using the VolunteerID from the requestData
        const volunteerId = requestData.VolunteerID;
        let volunteerName = 'Unknown';
        if (volunteerId) {
            try {
                const volunteerSnapshot = await db.collection('Volunteers').doc(volunteerId).get();
                volunteerName = volunteerSnapshot.exists ? volunteerSnapshot.data().Name : 'Unknown';
            } catch (error) {
                console.error('Error fetching volunteer data:', error.message);
            }
        }
        

        // Fetch review data related to the request
        const reviewSnapshot = await db.collection('Reviews').where('RequestID', '==', requestId).limit(1).get();
        let reviewData = null;
        if (!reviewSnapshot.empty) {
            const review = reviewSnapshot.docs[0].data();
            

            reviewData = {
                Feedback: review.Feedback,
                Rating: review.Rating
            };
        }

        // Respond with the request details and review
        res.status(200).send({
            Timestamp: timestamp,
            Status: requestData.Status,
            acceptedTime: acceptedTime,
            finishedTime: finishedTime,
            Duration: duration,
            Location: address,
            VolunteerName: volunteerName,
            Review: reviewData
        });

    } catch (error) {
        console.error('Error fetching finished request details', error);
        res.status(500).send({ error: 'Server error' });
    }
});





/**
 * @swagger
 * /user/profile/{userId}:
 *   get:
 *     summary: Get user information
 *     tags: [Profile]
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         description: The ID of the user to retrieve
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User information retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 Email:
 *                   type: string
 *                   description: The email of the user 
 *                 Name:
 *                   type: string
 *                   description: The name of the user
 *                 PhoneContact:
 *                   type: string
 *                   description: The password of the user
 *       400:
 *         description: Invalid user ID
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */


//SEE USER INFORMATIONS (EMAIL, NAME, PHONECONTACT)
router.get('/profile', authenticateToken, async (req, res) => {
//router.get('/profile/:userId', async (req, res) => {
    try {
        const userId = req.user.UserId;
        //const userId = req.params.userId;
        if (!userId) {
            return res.status(400).send({ error: 'Invalid userId' });
        }
        const UserRef = await db.collection('Users').doc(userId)
        const user = await UserRef.get();
        if (!user.exists) {
            return res.status(404).send({ error: 'User not found' });
        }
        const userData = user.data();
        const { Password, ...userWithoutPassword } = userData;

        res.status(200).send(userWithoutPassword);
    } catch (error) {
        console.error('Error in finding user:', error);
        res.status(500).send({ error: 'Server error' });
    }
});


/**
 * @swagger
 * /user/updateProfile/{userId}:
 *   patch:
 *     summary: Update name and phone contact
 *     tags: [Profile]
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         description: The ID of the user to update
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               Name:
 *                 type: string
 *                 description: The new name of the user
 *               PhoneContact:
 *                 type: string
 *                 pattern: ^\d+$  
 *                 description: The new phone contact of the user
 *     responses:
 *       200:
 *         description: User data updated successfully
 *       400:
 *         description: Invalid user ID or phone number
 *       500:
 *         description: Server error
 */

//UPDATE USER NAME AND PHONE CONTACT
router.patch('/updateProfile', authenticateToken, async (req, res) => {
//router.patch('/updateProfile/:userId', async (req, res) => {
    try {
        const userId = req.user.UserId;
        //const userId = req.params.userId;
        if (!userId) {
            return res.status(400).send({ error: 'Invalid userId' });
        }
        const { Name, PhoneContact } = req.body;
        const updateFields = {};
        
        if (Name) updateFields.Name = Name;
        
        if (PhoneContact) {
            // Verifies if the phone contact contains only digits
            if (!isValidPhoneNumber(PhoneContact)) {
                return res.status(400).send({ error: 'Invalid phone number format.' });
            }

            // Verifies if the phone contact already exists in the database 
            const existingUsersWithPhone = await db.collection('Users')
                .where('PhoneContact', '==', PhoneContact)
                .get();

            let phoneExists = false;
            existingUsersWithPhone.forEach(doc => {
                if (doc.id !== userId) {
                    phoneExists = true;
                }
            });

            if (phoneExists) {
                return res.status(400).send({ error: 'Phone number already exists for another user.' });
            }

            updateFields.PhoneContact = PhoneContact;
        }

        const userRef = db.collection('Users').doc(userId);
        await userRef.update(updateFields);

        res.status(200).send({ message: 'User data updated successfully' });
    } catch (error) {
        console.error('Error in updating information', error);
        res.status(500).send({ error: 'Server error' });
    }
});


/**
 * @swagger
 * /user/updatePassword/{userId}:
 *   patch:
 *     summary: Update password
 *     tags: [Profile]
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         description: The ID of the user to update
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               newPassword:
 *                 type: string
 *               confirmNewPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: Password updated successfully
 *       400:
 *         description: Invalid user ID or password format
 *       500:
 *         description: Server error
 */

//UPDATE PASSWORD
router.patch('/updatePassword', authenticateToken, async (req, res) => {
    try {
        
        const userId = req.user.UserId;
        console.log('Decoded UserID from token:', userId);


        if (!userId) {
            return res.status(400).send({ error: 'Invalid userId' });
        }

        const { newPassword, confirmNewPassword } = req.body;

        if (!newPassword || !confirmNewPassword) {
            return res.status(400).send({ error: 'Both password fields are required' });
        }

        if (!comparePasswords(newPassword, confirmNewPassword)) {
            return res.status(400).send({ error: 'Passwords do not match' });
        }

        const userDoc = await db.collection('Users').doc(userId).get();
        if (!userDoc.exists) {
            return res.status(404).send({ error: 'User not found' });
        }

        const userData = userDoc.data();

        // Verifies if the new password matches the old password 
        const passwordMatch = await bcrypt.compare(newPassword, userData.Password);
        if (passwordMatch) {
            return res.status(400).send({ error: 'New password cannot be the same as the old password' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.collection('Users').doc(userId).update({ Password: hashedPassword });

        return res.status(200).send({ message: 'Password updated successfully' });

    } catch (error) {
        console.error('Error in updating password', error);
        return res.status(500).send({ error: 'Server error' });
    }
});


/**
 * @swagger
 * /user/delete:
 *   delete:
 *     summary: Delete a user by ID
 *     tags: [Profile]
 *     parameters:
 *       - in: query
 *         name: userID
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the user to be deleted
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       400:
 *         description: Invalid user ID
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */



// DELETE USER (userID)
router.delete('/delete', authenticateToken, async (req, res) => {
//router.delete('/delete', async (req, res) => {
    try {
        //const { userID } = req.query;
        const userID = req.user.UserId;

        if (!userID) {
            return res.status(400).send({ error: 'Invalid user ID' });
        }

        const userRef = db.collection('Users').doc(userID);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            return res.status(404).send({ error: 'User not found' });
        }

        await userRef.delete();

        res.status(200).send({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error occurred during user deletion:', error);
        res.status(500).send({ error: 'Server error' });
    }
});




/**
 * @swagger
 * /user/history/{userId}:
 *   get:
 *     summary: Get user's request history ordered by most recent
 *     tags: [Requests]
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         description: The ID of the user to fetch request history
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: user's request history retrieved successfully, ordered by most recent
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               description: Array of requests ordered by most recent
 *               items:
 *                 type: object
 *                 properties:
 *                   Address:
 *                     type: string
 *                     description: The address of the request location
 *                   Status:
 *                     type: string
 *                     description: The status of the request
 *                   Timestamp:
 *                     type: string
 *                     format: date-time
 *                     description: The timestamp of the request
 *                   Duration:
 *                     type: string
 *                     description: The duration of the request
 *                   VolunteerName:
 *                     type: string
 *                     description: The name of the volunteer assigned to the request
 *       400:
 *         description: Invalid userId
 *       404:
 *         description: No requests found for the user
 *       500:
 *         description: Server error
 */

// REQUEST HISTORY (LOCATION, TIMESTAMP, VOLUNTEER, STATUS, DURATION OF EACH REQUEST)
//router.get('/history/:userId', async (req, res) => {
router.get('/history', authenticateToken, async (req, res) => {
    try {
        //const userId = req.params.userId;
        const userId = req.user.UserId;

        if (!userId) {
            return res.status(400).send({ error: 'Invalid userId' });
        }

        const userRequestsRef = db.collection('Requests').where('UserID', '==', userId);
        const userRequestsSnapshot = await userRequestsRef.get();

        if (userRequestsSnapshot.empty) {
            return res.status(404).send({ message: 'No requests found for the user' });
        }

        const requests = [];

        for (const doc of userRequestsSnapshot.docs) {
            const request = doc.data();

            let volunteerName = 'Unknown'; // Default value

            // Verifies if VolunteerID exists in the document
            if (request.VolunteerID) {
                try {
                    // Fetch volunteer information
                    const volunteerSnapshot = await db.collection('Volunteers').doc(request.VolunteerID).get();
                    if (volunteerSnapshot.exists) {
                        volunteerName = volunteerSnapshot.data().Name;
                    }
                } catch (error) {
                    console.error(`Error fetching volunteer with ID ${request.VolunteerID}:`, error.message);
                }
            }

            // Get the location address
            const { latitude, longitude } = request.Location || {}; // Ensure Location exists
            let address = 'Unknown location';
            if (latitude && longitude) {
                try {
                    const response = await axios.get(`https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${latitude}&lon=${longitude}`, {
                        headers: {
                          'User-Agent': 'Helper (helper.mobile.app.2024@gmail.com)' 
                        }
                      });                    
                      if (response.data) {
                        address = response.data.display_name;
                    }
                } catch (error) {
                    console.error('Error fetching address:', error.message);
                }
            }

            // Format the timestamp
            const formattedTimestamp = DateTime.fromMillis(request.Timestamp._seconds * 1000).setZone('Europe/Lisbon').toFormat('EEE, dd MMM yyyy HH:mm:ss');

            // Create the request object
            const requestObject = {
                Address: address,
                Status: request.Status,
                Timestamp: formattedTimestamp,
                Duration: request.Duration || 'N/A',
                VolunteerName: volunteerName
            };

            requests.push(requestObject);
        }

        // Sort requests by timestamp in descending order (most recent first)
        requests.sort((a, b) => new Date(b.Timestamp) - new Date(a.Timestamp));

        res.status(200).send(requests);

    } catch (error) {
        console.error('Error in fetching requests', error);
        res.status(500).send({ error: 'Server error' });
    }
});

// LOGOUT
router.post('/logout', authenticateToken, async (req, res) => {
    const userID = req.user.UserId;

        const requestsSnapshot = await db.collection('Requests')
            .where('UserID', '==', userID)
            .where('Status', 'in', ['accepted', 'pendent']) // This handles the 'OR' condition
            .get();

        const batch = db.batch();
        requestsSnapshot.forEach(doc => {
            const requestRef = db.collection('Requests').doc(doc.id);
            batch.update(requestRef, { Status: 'cancelled' });
        });

        await batch.commit();
    res.status(200).send({ message: 'Logged out successfully.' });
});



module.exports = router;
