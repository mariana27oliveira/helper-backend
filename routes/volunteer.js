const {Router} = require ('express');
const { FieldValue } = require('firebase-admin/firestore')
const admin = require('firebase-admin')
const { db } = require('../database/firebase.js')
const bcrypt = require('bcrypt');
const { comparePassword } = require('../utils/hashPassword.js');
const passport = require ('passport');
const googleStrategy = require('../strategies/google.js');
const axios = require('axios');
const { format } = require('date-fns');
const { ptBR } = require('date-fns/locale');

require('dotenv').config();

const bodyParser = require('body-parser');


const router = Router ();


router.use(bodyParser.json());


console.log(process.env.JWT_SECRET)

const jwt = require('jsonwebtoken');
const secretKey = process.env.JWT_SECRET; 

function generateAccessToken(volunteerId) {
    return jwt.sign({ VolunteerId: volunteerId }, secretKey, { expiresIn: '1h' });
}


function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) return res.status(401).send({ error: 'Failed to authenticate token' });
        req.volunteer = decoded; // Decoded objects contains VolunteerId 
        next();
    });
}

const authenticateFCMToken = async (req, res, next) => {
    try {
        // Obtains the authorization header 
        const authHeader = req.headers['authorization'];
        const fcmToken = authHeader && authHeader.split(' ')[1];

        // Verifies if the token is present 
        if (!fcmToken) {
            return res.sendStatus(401); // Unauthorized
        }

        const decodedToken = await admin.auth().verifyIdToken(fcmToken);

        // Adds decodedToken to the req object, to use later
        req.volunteer = decodedToken; // Decoded object contains volunteer id

        next(); 
    } catch (error) {
        console.error('Error in authenticateFCMToken:', error);
        res.status(401).send({ error: 'Failed to authenticate token' });
    }
};


const loggedInVolunteers = new Set(); // Stores the ids of the logged in volunteers 



/**
 * @swagger
 * tags:
 *   name: Authentication
 *   description: Operations related to volunteer authentication
 */

/**
 * @swagger
 * tags:
 *   name: Requests
 *   description: Operations related to volunteer requests
 */

/**
 * @swagger
 * tags:
 *   name: Profile
 *   description: Operations related to volunteer profile
 */



/**
 * @swagger
 * /volunteer/signup:
 *   post:
 *     summary: Create a new volunteer
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
 *               Location:
 *                 type: object
 *                 properties:
 *                   latitude:
 *                     type: number
 *                   longitude:
 *                     type: number
 *     responses:
 *       200:
 *         description: Volunteer created successfully
 *       400:
 *         description: Invalid input data
 *       500:
 *         description: Server error
 */


//SIGNUP (NAME, PASSWORD, EMAIL, PHONECONTACT)
router.post('/signup', async (req, res) => {
    try {
        const { Name, Email, Password, PhoneContact, ConfirmPassword, Location } = req.body;
        if (!Name || !Email || !Password || !PhoneContact) {
            return res.status(400).send({ error: 'All fields are required.' });
        }

        if (!isValidEmail(Email)) {
            return res.status(400).send({ error: 'Invalid email format.' });
        }

        // Verifies if passwords match
        if (Password !== ConfirmPassword) {
            return res.status(400).send({ error: 'Passwords do not match.' });
        }

        const existingVolunteerWithEmail = await db.collection('Volunteers').where('Email', '==', Email).get();
        if (!existingVolunteerWithEmail.empty) {
            return res.status(400).send({ error: 'Email already exists.' });
        }

        if (!isValidPhoneNumber(PhoneContact)) {
            return res.status(400).send({ error: 'Invalid phone number format.' });
        }

        const existingVolunteerWithPhone = await db.collection('Volunteers').where('PhoneContact', '==', PhoneContact).get();
        if (!existingVolunteerWithPhone.empty) {
            return res.status(400).send({ error: 'Phone number already exists.' });
        }

        // Hash password before saving it in the data base 
        const hashedPassword = await bcrypt.hash(Password, 10);


        const newVolunteerRef = await db.collection('Volunteers').add({
            Name: Name,
            Password: hashedPassword,
            Email: Email,
            PhoneContact: PhoneContact,
            Points: 0,
            Badges: []
        });


        // Creates a GeoPoint object, latitude and longitude
        const volunteerLocation = new admin.firestore.GeoPoint(Location.latitude, Location.longitude);

        // Saves the volunteer location in 'LocationVolunteers' collection
        await db.collection('LocationVolunteers').doc(newVolunteerRef.id).set({
            Location: volunteerLocation
        });

        loggedInVolunteers.add(newVolunteerRef.id);

        console.log(loggedInVolunteers)

        // Generates a token JWT
        const jwtToken = generateAccessToken(newVolunteerRef.id);

        // Store the FCM token in the database
        await db.collection('Volunteers').doc(newVolunteerRef.id).set({
            fcmToken: req.body.fcmToken
        }, { merge: true });
        
        
        res.status(200).send({ 
            message: 'Volunteer added successfully',
            VolunteerID: newVolunteerRef.id,
            token: jwtToken 
        });

    } catch (error) {
        console.error('Error occurred during user signup:', error);
        res.status(500).send({ error: 'Server error' });
    }
});

function isValidEmail(email) {
    return /\S+@\S+\.\S+/.test(email);
}

function isValidPhoneNumber(phone) {
    return /^\d{9}$/.test(phone);
}

let googleLocation = {};
let fcmTokenGoogle = {};

router.get('/google', (req, res, next) => {
    const { latitude, longitude, fcmToken } = req.query;
    fcmTokenGoogle = fcmToken;
    console.log(fcmTokenGoogle);
    console.log(`Localização do usuário: Latitude - ${latitude}, Longitude - ${longitude}`);
    if (latitude && longitude) {
        req.session.location = { latitude, longitude };
    }

    googleLocation = { latitude, longitude };

    next(); 
}, passport.authenticate('volunteer-google'));



router.get('/google/redirect', passport.authenticate('volunteer-google'), async (req, res) => {
    const { id: googleId } = req.user;

    volunteerSnapshot = await db.collection('Volunteers').doc(googleId).get();
    if (volunteerSnapshot.exists) {
        // Store the FCM token in the database
        await db.collection('Volunteers').doc(googleId).set({
            fcmToken: fcmTokenGoogle
        }, { merge: true });
    }

    const { latitude, longitude } = googleLocation || {};
    console.log(`Localização do usuário: Latitude - ${latitude}, Longitude - ${longitude}`);


    if (latitude && longitude) {
        // Converts latitude and longitude to number
        const lat = parseFloat(latitude);
        const lng = parseFloat(longitude);

        if (!isNaN(lat) && !isNaN(lng)) {
            const volunteerLocation = new admin.firestore.GeoPoint(lat, lng);

            // Stores the location in the 'LocationVolunteers' collection
            await db.collection('LocationVolunteers').doc(googleId).set({
                Location: volunteerLocation
            });

            console.log(`Localização do usuário: Latitude - ${lat}, Longitude - ${lng}`);
        } else {
            console.error('Latitude ou longitude inválidos.');
        }
    }

    delete googleLocation;

    // Generates jet token and redirects 
    const token = generateAccessToken(googleId);
    const redirectUrl = `myapp://success?id=${googleId}&token=${token}`;
    res.redirect(redirectUrl);
});




/**
 * @swagger
 * /volunteer/add/{volunteerId}:
 *   patch:
 *     summary: Add phone contact 
 *     tags: [Authentication]
 *     parameters:
 *       - in: path
 *         name: volunteerId
 *         required: true
 *         description: The ID of the volunteer
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
 *                 description: The new phone contact of the volunteer
 *     responses:
 *       200:
 *         description: Volunteer phone contact added successfully
 *       400:
 *         description: Invalid volunteer ID
 *       500:
 *         description: Server error
 */

//SAVE AND ADD PHONE CONTACT
router.patch('/add/:googleId', async (req, res) => {
    try {

        const { googleId } = req.params;
        const { PhoneContact } = req.body;
        if (!googleId) {
            return res.status(400).send({ error: 'Invalid googleId' });
        }


        //Verifies if googleId already exists in "Volunteers" collection
        const volunteerDoc = await db.collection('Volunteers').doc(googleId).get();
        if (volunteerDoc.exists) {
            return res.status(400).send({ error: 'This email already has an account, please go to login' });
        }

        // Verifies if the PhoneContact already exists in 'Volunteers' collection
        const userWithPhoneContact = await db.collection('Volunteers')
            .where('PhoneContact', '==', PhoneContact)
            .get();

        if (!userWithPhoneContact.empty) {
            return res.status(400).send({ error: 'Phone contact already exists' });
        }


        const googleDoc = await db.collection('GoogleUsers').doc(googleId).get();

        const googleUserData = googleDoc.data();
    

        // Creates a new document in 'Volunteers' collection
        await db.collection('Volunteers').doc(googleId).set({
          Name: googleUserData.displayName,
          Email: googleUserData.email,
          PhoneContact: PhoneContact,
          Points: 0,
          Badges: []
        });

        // Store the FCM token in the database
        await db.collection('Volunteers').doc(googleId).set({
            fcmTokenGoogle
        }, { merge: true });

    
        return res.status(201).send('Volunteer created successfully');
      } catch (error) {
        console.error('Error creating user:', error);
        return res.status(500).send('Error creating volunteer');
      }
    });
    


/**
 * @swagger
 * /volunteer/login:
 *   post:
 *     summary: Authenticate volunteer
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
 *         description: Volunteer not found or wrong password
 *       500:
 *         description: Server error
 */


//LOGIN (EMAIL, PASSWORD)
router.post('/login', async (req, res) => {
    try {
        const { Email, Password, Location } = req.body;
        if (!Email || !Password) {
            return res.status(400).send({ error: 'Missing credentials' });
        }
        const volunteer = await db.collection('Volunteers').where('Email', '==', Email).limit(1).get();
        if (volunteer.empty) {
            return res.status(401).send({ error: 'Volunteer not found.' });
        }
        const volunteerData = volunteer.docs[0].data();
        const volunteerId = volunteer.docs[0].id;
        
        // Update volunteer's location in LocationVolunteers collection
        const volunteerLocation = new admin.firestore.GeoPoint(Location.latitude, Location.longitude);
        await db.collection('LocationVolunteers').doc(volunteerId).set({
            Location: volunteerLocation
        }, { merge: true });

        const passwordMatch = comparePassword(Password, volunteerData.Password); 
        
        if (!passwordMatch) {
            return res.status(401).send({ error: 'Wrong password' });
        }

        loggedInVolunteers.add(volunteerId);
        console.log(loggedInVolunteers);

        const jwtToken = generateAccessToken(volunteerId);

        // Store the FCM token in the database
        await db.collection('Volunteers').doc(volunteerId).set({
            fcmToken: req.body.fcmToken
        }, { merge: true });

        res.status(200).send({ 
            message: 'Authentication successful',
            token: jwtToken,
            volunteerId: volunteerId 
        });

    } catch (error) {
        console.error('Login failed', error);
        res.status(500).send({ error: 'Server error' });        
    }
});

// Updates registration token (FCM)
router.post('/updateToken', authenticateFCMToken, async (req, res) => {
    try {
        const { volunteerId, fcmToken } = req.body;

        // Verifies if the volunteer id or token are missing 
        if (!volunteerId || !fcmToken) {
            return res.status(400).send({ error: 'Missing volunteerId or token' });
        }

        // Updates fcm token of the volunteer in the database 
        await db.collection('Volunteers').doc(volunteerId).set({
            fcmToken: fcmToken
        }, { merge: true }); // 'merge: true' - updates without overwriting 

        res.status(200).send({ message: 'Token updated successfully' });
    } catch (error) {
        console.error('Error updating token', error);
        res.status(500).send({ error: 'Server error' }); 
    }
});



//OBTAINS LOGGED IN VOLUNTEERS 
router.get('/loggedInVolunteers', authenticateToken, async (req, res) => {
    try {
        // Obtains the list of volunteers id that are logged in
        const volunteerIDs = Array.from(loggedInVolunteers); 

        res.status(200).json(volunteerIDs);
    } catch (error) {
        console.error('Error fetching logged-in volunteers', error);
        res.status(500).send({ error: 'Server error' });
    }
});


const nodemailer = require('nodemailer');


const transporter = nodemailer.createTransport({
    service: 'Gmail', // it can be other service
    auth: {
        user: 'helper.mobile.app.2024@gmail.com',
        pass: 'tgtp uvwq btrk mcad'
    }
});

// Function to send the email
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
 * /volunteer/forgot_password_1:
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
 *                 volunteerId:
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

        const volunteerSnapshot = await db.collection('Volunteers').where('Email', '==', Email).get();

        if (volunteerSnapshot.empty) {
            return res.status(404).send({ error: 'Email not found' });
        }

        const volunteerDoc = volunteerSnapshot.docs[0];
        const volunteerId = volunteerDoc.id;

        // Generates a verification code 
        const verificationCode = Math.floor(1000 + Math.random() * 9000); 
        console.log(`Generated verification code: ${verificationCode}`);

        // Stores the verification code in the database 
        await db.collection('Volunteers').doc(volunteerId).update({ verificationCode });

        // Send the verificatio conde 
        await sendEmail(
            Email,
            'Password Recovery Code',
            `Your password recovery code is ${verificationCode}`
        );

        return res.status(200).send({ message: 'Email sent successfully', volunteerId });

    } catch (error) {
        console.error('Error in forgot_password_1', error);
        return res.status(500).send({ error: 'Server error' });
    }
});


router.post('/forgot_password_2', async (req, res) => {
    try {
        const { volunteerId, verificationCode } = req.body;
        console.log(`Verification attempt for volunteerId: ${volunteerId} with code: ${verificationCode}`); 
        // Verifies if the code given matches the code stored in db 
        const volunteerDoc = await db.collection('Volunteers').doc(volunteerId).get();
        if (!volunteerDoc.exists) {
            return res.status(404).send({ error: 'Volunteer not found' });
        }

        const volunteerData = volunteerDoc.data();
        console.log(`Stored verification code: ${volunteerData.verificationCode}, Provided code: ${verificationCode}`); 
        if (volunteerData.verificationCode != verificationCode) {
            return res.status(400).send({ error: 'Invalid verification code' });
        }

        // If the code is valid, the code stored is deleted
        await db.collection('Volunteers').doc(volunteerId).update({ verificationCode: null });

        return res.status(200).send({ message: 'Verification code valid' });

    } catch (error) {
        console.error('Error in forgot_password_2', error);
        return res.status(500).send({ error: 'Server error' });
    }
});

/**
 * @swagger
 * /volunteer/forgot_password_3/{volunteerId}:
 *   post:
 *     summary: Forgot Password (3)
 *     tags: [Authentication]
 *     parameters:
 *       - in: path
 *         name: volunteerId
 *         required: true
 *         description: The ID of the volunteer to update
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
 *         description: Volunteer not found
 *       500:
 *         description: Server error
 */

const comparePasswords = (password1, password2) => password1 === password2;

router.post('/forgot_password_3/:volunteerId', async (req, res) => {
    try {
        const { volunteerId } = req.params; 
        const { newPassword, confirmNewPassword } = req.body; 
        console.log(`Received volunteerId: ${volunteerId}`);

        if (!newPassword || !confirmNewPassword) {
            return res.status(400).send({ error: 'All fields are required' });
        }

        if (!comparePasswords(newPassword, confirmNewPassword)) {
            return res.status(400).send({ error: 'Passwords do not match' });
        }

        const volunteerDoc = await db.collection('Volunteers').doc(volunteerId).get();

        if (!volunteerDoc.exists) {
            return res.status(404).send({ error: 'Volunteer not found' });
        }

        const volunteerData = volunteerDoc.data();
        const hashedPassword = volunteerData.Password; 

        const passwordMatch = await bcrypt.compare(newPassword, hashedPassword);
        if (passwordMatch) {
            return res.status(400).send({ error: 'New password cannot be the same as the old password' });
        }

        const newHashedPassword = await bcrypt.hash(newPassword, 10);

        await db.collection('Volunteers').doc(volunteerId).update({ Password: newHashedPassword });

        return res.status(200).send({ message: 'Password updated successfully' });

    } catch (error) {
        console.error('Error in forgot_password_3', error);
        return res.status(500).send({ error: 'Server error' });
    }
});



/**
 * @swagger
 * /volunteer/activeRequests/{volunteerId}:
 *   post:
 *     summary: Get all active requests with status 'pendent' for a volunteer
 *     tags: [Requests]
 *     parameters:
 *       - in: path
 *         name: volunteerId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the volunteer to get active requests for
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *                  latitude:
 *                    type: number
 *                  longitude:
 *                    type: number
 *     responses:
 *       200:
 *         description: A list of active requests with user names, time elapsed, and distance from volunteer, along with city and country of the volunteer's location
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 city:
 *                   type: string
 *                   description: The city where the volunteer is located
 *                 country:
 *                   type: string
 *                   description: The country where the volunteer is located
 *                 activeRequests:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                         description: The request ID
 *                       userName:
 *                         type: string
 *                         description: The name of the user who made the request
 *                       timeElapsed:
 *                         type: string
 *                         description: The time elapsed since the request was made, in minutes, hours, or days
 *                       distance:
 *                         type: string
 *                         description: The distance in kilometers between the volunteer and the request location
 *       400:
 *         description: Bad request, possibly due to invalid volunteer ID or location data
 *       404:
 *         description: Volunteer location not found or no active requests found
 *       500:
 *         description: Server error
 */



// GET ACTIVE REQUESTS (Status: 'pendent')
//router.post('/activeRequests/:volunteerId', async (req, res) => {
router.post('/activeRequests', authenticateToken, async (req, res) => {
    try {
        const volunteerId = req.volunteer.VolunteerId;
        //const volunteerId = req.params.volunteerId;

        const { latitude, longitude } = req.body;


        const volunteerLocationRef = db.collection('LocationVolunteers').doc(volunteerId);
        await volunteerLocationRef.set({
            Location: new admin.firestore.GeoPoint(latitude, longitude),
        }, { merge: true });


        // Get volunteer location
        const volunteerLocationDoc = await db.collection('LocationVolunteers').doc(volunteerId).get();
        if (!volunteerLocationDoc.exists) {
            return res.status(404).send({ error: 'Volunteer location not found.' });
        }

        const volunteerLocation = volunteerLocationDoc.data();
        const volunteerLat = volunteerLocation.Location.latitude;
        const volunteerLng = volunteerLocation.Location.longitude;

        // Obtain city and country
        const geocodingApiUrl = `https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${volunteerLat}&lon=${volunteerLng}`;

        const geoResponse = await axios.get(geocodingApiUrl, {
            headers: {
                'User-Agent': 'Helper (helper.mobile.app.2024@gmail.com)' 
            }
        });

        const geoData = geoResponse.data;

        let city = 'Unknown City';
        let country = 'Unknown Country';

        if (geoData.address) {
            city = geoData.address.city || geoData.address.town || geoData.address.village || 'Unknown City';
            country = geoData.address.country || 'Unknown Country';
        }

        // Get all active requests
        const requestsSnapshot = await db.collection('Requests').where('Status', '==', 'pendent').get();
        if (requestsSnapshot.empty) {
            return res.status(200).send({
                city: city,
                country: country,
                message: 'There are no pending requests.'
            });
        }
        

        const activeRequests = [];
        for (const doc of requestsSnapshot.docs) {
            const requestData = doc.data();

            // Get user name from Users collection
            const userDoc = await db.collection('Users').doc(requestData.UserID).get();
            if (!userDoc.exists) {
                console.error(`User not found for request ID: ${doc.id}`);
                continue;
            }
            const userName = userDoc.data().Name;

            // Calculate time elapsed since the request was made
            const requestTime = requestData.Timestamp.toDate();
            const currentTime = new Date();
            const timeElapsed = Math.floor((currentTime - requestTime) / 60000); // Time in minutes

            let timeElapsedString;
            if (timeElapsed < 60) {
                timeElapsedString = `${timeElapsed} minutes ago`;
            } else if (timeElapsed < 1440) { // Less than 24 hours
                const hoursElapsed = Math.floor(timeElapsed / 60);
                timeElapsedString = `${hoursElapsed} hours ago`;
            } else {
                const daysElapsed = Math.floor(timeElapsed / 1440);
                timeElapsedString = `${daysElapsed} days ago`;
            }

            // Calculate distance between volunteer and request location
            const requestLat = requestData.Location.latitude;
            const requestLng = requestData.Location.longitude;
            const distance = calculateDistance(volunteerLat, volunteerLng, requestLat, requestLng);

            // Push formatted data to the activeRequests array
            activeRequests.push({
                id: doc.id,
                userName: userName,
                timeElapsed: timeElapsedString,
                distance: distance 
            });
        }

        // Sort active requests by distance (closest first)
        activeRequests.sort((a, b) => a.distance - b.distance);

        // Format the distance to be displayed as "x.xx km"
        const formattedRequests = activeRequests.map(request => ({
            ...request,
            distance: `${request.distance.toFixed(1)} km`
        }));

        res.status(200).send({
            city: city,
            country: country,
            activeRequests: formattedRequests
    });
    } catch (error) {
        console.error('Error occurred while fetching active requests:', error);
        res.status(500).send({ error: 'Server error' });
    }
});

// Function to calculate distance between two points using Haversine formula
function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371; // Radius of the Earth in km
    const dLat = degreesToRadians(lat2 - lat1);
    const dLon = degreesToRadians(lon2 - lon1);
    const a =
        Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(degreesToRadians(lat1)) * Math.cos(degreesToRadians(lat2)) *
        Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    const distance = R * c; // Distance in km
    return distance;
}

function degreesToRadians(degrees) {
    return degrees * (Math.PI / 180);
}

/**
 * @swagger
 * /volunteer/activeRequestsALL/{volunteerId}:
 *   get:
 *     summary: Get all active requests with status 'pendent'
 *     tags: [Requests]
 *     parameters:
 *       - in: path
 *         name: volunteerId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the volunteer to calculate the distance and fetch relevant data
 *     responses:
 *       200:
 *         description: A list of active requests with user names, time elapsed, and distance from volunteer
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: string
 *                     description: The request ID
 *                   userName:
 *                     type: string
 *                     description: The name of the user who made the request
 *                   timeElapsed:
 *                     type: string
 *                     description: The time elapsed since the request was made, in minutes or hours
 *                   distance:
 *                     type: string
 *                     description: The distance in kilometers between the volunteer and the request location
 *       500:
 *         description: Server error
 */

// GET ACTIVE REQUESTS (Status: 'pendent')
//router.get('/activeRequestsALL/:volunteerId', async (req, res) => {
    router.get('/activeRequestsALL', authenticateToken, async (req, res) => {
        try {
            const volunteerId = req.volunteer.VolunteerId;
            //const volunteerId = req.params.volunteerId;
            // Get volunteer location
            const volunteerLocationDoc = await db.collection('LocationVolunteers').doc(volunteerId).get();
            if (!volunteerLocationDoc.exists) {
                return res.status(404).send({ error: 'Volunteer location not found.' });
            }
            const volunteerLocation = volunteerLocationDoc.data();
            const volunteerLat = volunteerLocation.Location.latitude;
            const volunteerLng = volunteerLocation.Location.longitude;
            // Get all active requests
            const requestsSnapshot = await db.collection('Requests').where('Status', '==', 'pendent').get();
            if (requestsSnapshot.empty) {
                return res.status(200).send({ message: 'There are no pending requests.' });
            }
            
            const activeRequests = [];
            for (const doc of requestsSnapshot.docs) {
                const requestData = doc.data();
                // Get user name from Users collection
                const userDoc = await db.collection('Users').doc(requestData.UserID).get();
                if (!userDoc.exists) {
                    console.error(`User not found for request ID: ${doc.id}`);
                    continue;
                }
                const userName = userDoc.data().Name;
                // Calculate time elapsed since the request was made
                const requestTime = requestData.Timestamp.toDate();
                const currentTime = new Date();
                const timeElapsed = Math.floor((currentTime - requestTime) / 60000); // Time in minutes
                let timeElapsedString;
                if (timeElapsed < 60) {
                    timeElapsedString = `${timeElapsed} minutes ago`;
                } else if (timeElapsed < 1440) { // Less than 24 hours
                    const hoursElapsed = Math.floor(timeElapsed / 60);
                    timeElapsedString = `${hoursElapsed} hours ago`;
                } else {
                    const daysElapsed = Math.floor(timeElapsed / 1440);
                    timeElapsedString = `${daysElapsed} days ago`;
                }
                // Calculate distance between volunteer and request location
                const requestLat = requestData.Location.latitude;
                const requestLng = requestData.Location.longitude;
                const distance = calculateDistance(volunteerLat, volunteerLng, requestLat, requestLng);
                // Push formatted data to the activeRequests array
                activeRequests.push({
                    id: doc.id,
                    userName: userName,
                    timeElapsed: timeElapsedString,
                    distance: distance 
                });
            }
            // Sort active requests by distance (closest first)
            activeRequests.sort((a, b) => a.distance - b.distance);
            // Format the distance to be displayed as "x.xx km"
            const formattedRequests = activeRequests.map(request => ({
                ...request,
                distance: `${request.distance.toFixed(1)} km`
            }));
            res.status(200).send(formattedRequests);
        } catch (error) {
            console.error('Error occurred while fetching active requests:', error);
            res.status(500).send({ error: 'Server error' });
        }
    });



/**
 * @swagger
 * /volunteer/request_info/{volunteerId}/{requestId}:
 *   get:
 *     summary: Get request information including user name, time elapsed, distance, status, and Google Maps link
 *     tags: [Requests]
 *     parameters:
 *       - in: path
 *         name: volunteerId
 *         required: true
 *         description: The ID of the volunteer whose location will be used to calculate the distance
 *         schema:
 *           type: string
 *       - in: path
 *         name: requestId
 *         required: true
 *         description: The ID of the request to retrieve the information for
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
 *                 Distance:
 *                   type: string
 *                   description: The distance in kilometers between the volunteer and the request location
 *                 Status:
 *                   type: string
 *                   description: The current status of the request
 *                 TimeElapsed:
 *                   type: string
 *                   description: The time elapsed since the request was made (in minutes, hours, or days)
 *                 UserName:
 *                   type: string
 *                   description: The name of the user who made the request
 *                 MapLink:
 *                   type: string
 *                   description: A Google Maps link to the request's location
 *       400:
 *         description: Invalid volunteerId or requestId
 *       404:
 *         description: Request or volunteer location not found
 *       500:
 *         description: Server error
 */


// SEE REQUEST INFORMATION (USER NAME, TIME ELAPSED, DISTANCE, STATUS, GOOGLE MAPS LINK)
router.get('/request_info/:requestId', authenticateToken, async (req, res) => {
//router.get('/request_info/:volunteerId/:requestId', async (req, res) => {
    try {
        const volunteerId = req.volunteer.VolunteerId;
        //const volunteerId = req.params.volunteerId;
        //const requestId = req.params.requestId;
        const { requestId } = req.params;
        if (!requestId) {
            return res.status(400).send({ error: 'Invalid requestId' });
        }

        // Retrieve the request document using the requestId
        const requestDoc = await db.collection('Requests').doc(requestId).get();
        if (!requestDoc.exists) {
            return res.status(404).send({ error: 'Request not found' });
        }

        const requestData = requestDoc.data();
        const { Location, Status, Timestamp, UserID } = requestData;


        // Check if the request status is "cancelled"
        if (Status === 'cancelled') {
            return res.status(400).send({ error: 'The request was cancelled' });
        }

        // Retrieve volunteer's location
        const volunteerLocationDoc = await db.collection('LocationVolunteers').doc(volunteerId).get();
        if (!volunteerLocationDoc.exists) {
            return res.status(404).send({ error: 'Volunteer location not found.' });
        }

        const volunteerLocation = volunteerLocationDoc.data();
        const volunteerLat = volunteerLocation.Location.latitude;
        const volunteerLng = volunteerLocation.Location.longitude;

        // Calculate time elapsed since the request was made
        const requestTime = Timestamp.toDate();
        const currentTime = new Date();
        const timeElapsed = Math.floor((currentTime - requestTime) / 60000); // Time in minutes
        let timeElapsedString;
        if (timeElapsed < 60) {
            timeElapsedString = `${timeElapsed} minutes ago`;
        } else if (timeElapsed < 1440) { // Less than 24 hours
            const hoursElapsed = Math.floor(timeElapsed / 60);
            timeElapsedString = `${hoursElapsed} hours ago`;
        } else {
            const daysElapsed = Math.floor(timeElapsed / 1440);
            timeElapsedString = `${daysElapsed} days ago`;
        }

        // Calculate distance between volunteer and request location
        const requestLat = Location.latitude;
        const requestLng = Location.longitude;
        const distance = calculateDistance(volunteerLat, volunteerLng, requestLat, requestLng);

        // Retrieve user details
        const userRef = db.collection('Users').doc(UserID);
        const userSnapshot = await userRef.get();
        let userName = 'Unknown';
        if (userSnapshot.exists) {
            const userData = userSnapshot.data();
            userName = userData.Name || 'Unknown';
        }

        // Prepare the response data
        const responseData = {
            RequestID: requestDoc.id,
            Distance: `${distance.toFixed(1)} km`, // Format distance
            Status: Status,
            TimeElapsed: timeElapsedString,
            UserName: userName,
            MapLink: `https://www.google.com/maps/search/?api=1&query=${Location.latitude},${Location.longitude}`
        };

        return res.status(200).send(responseData);
    } catch (error) {
        console.error('Error in finding request or calculating distance:', error);
        res.status(500).send({ error: 'Server error' });
    }
});


/**
 * @swagger
 * /volunteer/requests/{volunteerId}:
 *   get:
 *     summary: Get request information by volunteer ID
 *     tags: [Requests]
 *     parameters:
 *       - in: path
 *         name: volunteerId
 *         required: true
 *         description: The ID of the volunteer to retrieve the request for
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
 *                 Status:
 *                   type: string
 *                   description: The status of the request
 *                 Timestamp:
 *                   type: string
 *                   format: date-time
 *                   description: The timestamp of when the request was made
 *                 UserName:
 *                   type: string
 *                   description: The name of the user who made the request
 *                 UserPhoneContact:
 *                   type: string
 *                   description: The phone contact of the user
 *                 MapLink:
 *                   type: string
 *                   description: The Google Maps link to the request location
 *                 message:
 *                   type: string
 *                   description: Message indicating the status of the request (e.g., "The request was cancelled" or "There is no ongoing request for this volunteer.")
 *       400:
 *         description: Invalid volunteer ID
 *       404:
 *         description: Request not found
 *       500:
 *         description: Server error
 */



// SEE REQUEST INFORMATION (USER NAME and CONTACT, TIMESTAMP, LOCATION, STATUS, GOOGLE MAPS LINK) - OpenStreetMap Nominatim API
router.get('/requests', authenticateToken, async (req, res) => {
//router.get('/requests/:volunteerId', async (req, res) => {
    try {
        const volunteerId = req.volunteer.VolunteerId;
        //const volunteerId = req.params.volunteerId;
        if (!volunteerId) {
            return res.status(400).send({ error: 'Invalid volunteerId' });
        }

        // Find the request by VolunteerID and status 'accepted'
        const requestsSnapshot = await db.collection('Requests')
            .where('VolunteerID', '==', volunteerId)
            .where('Status', 'in', ['accepted', 'completed']) // This handles the 'OR' condition
            .limit(1) // Assuming only one request per volunteer with status 'accepted'
            .get();
        
        if (!requestsSnapshot.empty) {

        const request = requestsSnapshot.docs[0];
        const requestData = request.data();
        const { Location, Status, Timestamp, UserID } = requestData;

        // Retrieve user details
        const userRef = db.collection('Users').doc(UserID);
        const userSnapshot = await userRef.get();
        let userName = 'Unknown';
        let userPhoneContact = 'Unknown';
        if (userSnapshot.exists) {
            const userData = userSnapshot.data();
            userName = userData.Name || 'Unknown';
            userPhoneContact = userData.PhoneContact || 'Unknown';
        }

        // Get address from OpenStreetMap Nominatim API
        const response = await axios.get(`https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${Location.latitude}&lon=${Location.longitude}`, {
            headers: {
              'User-Agent': 'Helper (helper.mobile.app.2024@gmail.com)' 
            }
          });          
        if (response.data) {
            const address = response.data.display_name;
            const formattedTimestamp = DateTime.fromMillis(Timestamp._seconds * 1000).setZone('Europe/Lisbon').toFormat('EEE, dd MMM yyyy HH:mm:ss');
            const responseData = {
                RequestID: request.id, // Adding the RequestID
                Location: address,
                Status: Status,
                Timestamp: formattedTimestamp,
                UserName: userName,
                UserPhoneContact: userPhoneContact,
                MapLink: `https://www.google.com/maps/search/?api=1&query=${Location.latitude},${Location.longitude}`
            };
            return res.status(200).send(responseData);
        } else {
            return res.status(500).send({ error: 'Failed to retrieve address' });
        }
    }

// Searches for all the requests of the volunteer, sorted by timestamp
const volunteerRequestsSnapshot = await db.collection('Requests')
    .where('VolunteerID', '==', volunteerId)
    .orderBy('Timestamp', 'desc') 
    .limit(1)  
    .get();

if (volunteerRequestsSnapshot.empty) {
    return res.status(404).send({ message: 'No requests found for the volunteer' });
}

const mostRecentRequest = volunteerRequestsSnapshot.docs[0].data();

// Verifies if the most recent request has status 'cancelled' 
if (mostRecentRequest.Status === 'cancelled') {
    return res.status(200).send(mostRecentRequest);
}

        return res.status(200).send({ message: 'There is no ongoing request for this volunteer.' });


    } catch (error) {
        console.error('Error in finding request', error);
        res.status(500).send({ error: 'Server error' });
    }
});



/**
 * @swagger
 * /volunteer/updateRequest/{requestId}:
 *   patch:
 *     summary: Update request status or add volunteer
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
 *               VolunteerID:
 *                 type: string
 *                 description: The ID of the volunteer to be assigned to the request
 *     responses:
 *       200:
 *         description: Request updated successfully
 *       400:
 *         description: Invalid request ID
 *       500:
 *         description: Server error
 */


router.patch('/updateRequest/:requestId', authenticateToken, async (req, res) => {
    try {
        const requestId = req.params.requestId;
        if (!requestId) {
            return res.status(400).send({ error: 'Invalid requestId' });
        }

        const { Status } = req.body;
        const updateFields = {};

        if (Status) {
            updateFields.Status = Status;

            // Verifies if status is 'accepted'
            if (Status === 'accepted') {
                if (!req.volunteer || !req.volunteer.VolunteerId) {
                    return res.status(400).send({ error: 'Volunteer ID missing in token' });
                }

                const volunteerId = req.volunteer.VolunteerId;

                // Verifies if there is another request with status 'accepted' for this volunteer
                const existingAcceptedRequest = await db.collection('Requests')
                    .where('VolunteerID', '==', volunteerId)
                    .where('Status', '==', 'accepted')
                    .limit(1)  
                    .get();

                if (!existingAcceptedRequest.empty) {
                    return res.status(400).send({ error: 'Volunteer already has an accepted request' });
                }

                // If there is no other accepted request, adds the acceptedTime
                updateFields.acceptedTime = new Date();
            }

            if (Status === 'finished') {
                updateFields.finishedTime = new Date(); // Add finishedTime if status is finished
            }
        }

        // Use VolunteerID from the token
        if (req.volunteer && req.volunteer.VolunteerId) {
            updateFields.VolunteerID = req.volunteer.VolunteerId;
        }

        if (Status === "completed") {
            const requestDoc = await db.collection('Requests').doc(requestId).get();
            if (requestDoc.exists) {
                const requestData = requestDoc.data();
                if (requestData.Status === "completed") {
                    updateFields.Status = "finished";
                    updateFields.finishedTime = new Date(); // Update finishedTime if completed via any route
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
            
            // Calculates the difference between accepted time and finished time 
            const diffMs = finishedTime - acceptedTime;
            const diffMinutes = Math.round(diffMs / 60000); 

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
 * /volunteer/request_points_badges/{requestId}:
 *   get:
 *     summary: Retrieve total points and badges 
 *     tags: [Requests]
 *     description: Calculates and updates the total points and badges for a volunteer based on the specified request.
 *     parameters:
 *       - in: path
 *         name: requestId
 *         schema:
 *           type: string
 *         required: true
 *         description: The ID of the request
 *     responses:
 *       200:
 *         description: Points and badges updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 points:
 *                   type: integer
 *                 badges:
 *                   type: array
 *                   items:
 *                     type: string
 *       400:
 *         description: Invalid requestId, request is not finished, or volunteer not assigned to request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *       404:
 *         description: Request not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 */

// GET REQUEST POINTS AND BADGES
router.get('/request_points_badges/:requestId', async (req, res) => {
    try {
        const requestId = req.params.requestId;
        if (!requestId) {
            return res.status(400).send({ error: 'Invalid requestId' });
        }

        const requestDoc = await db.collection('Requests').doc(requestId).get();
        if (!requestDoc.exists) {
            return res.status(404).send({ error: 'Request not found' });
        }

        const requestData = requestDoc.data();
        if (!requestData.finishedTime) {
            return res.status(400).send({ error: 'Request is not finished' });
        }

        // Verifies if the points have already been counted 
        if (requestData.VolunteerPoints && requestData.VolunteerPoints > 0) {
            return res.status(200).send({ 
                message: 'Points have already been awarded', 
                Points: requestData.VolunteerPoints 
            });
        }

        const volunteerId = requestData.VolunteerID;
        if (!volunteerId) {
            return res.status(400).send({ error: 'Volunteer not assigned to request' });
        }

        let totalPoints = 5; // Points for finishing the request

        const acceptedTime = requestData.acceptedTime.toDate();
        const finishedTime = requestData.finishedTime.toDate();

        if (finishedTime - acceptedTime > 3600000) { // More than 1 hour
            totalPoints += 10;
        }

        // Check for reviews associated with this request ID
        const reviewsSnapshot = await db.collection('Reviews')
            .where('RequestID', '==', requestId)
            .get();

        if (!reviewsSnapshot.empty) {
            reviewsSnapshot.forEach(reviewDoc => {
                const reviewData = reviewDoc.data();
                if (reviewData.Rating > 4) {
                    totalPoints += 5;
                }
            });
        }

        const volunteerRequests = await getVolunteerRequests(volunteerId);
        const finishedDates = volunteerRequests
            .map(req => req.finishedTime ? req.finishedTime.toDate().toDateString() : null)
            .filter(date => date !== null);

        const uniqueFinishedDates = [...new Set(finishedDates)];
        uniqueFinishedDates.sort((a, b) => new Date(a) - new Date(b)); // Sort dates
        
        

        let Badges = [];

        function isWeekend(date) {
            const day = date.getDay();
            return day === 0 || day === 6; // Sunday or Saturday
        }

        const volunteerDoc = await db.collection('Volunteers').doc(volunteerId).get();
        if (volunteerDoc.exists) {
            const currentBadges = volunteerDoc.data().Badges || [];

            let consecutiveDays = 1;
        for (let i = 1; i < uniqueFinishedDates.length; i++) {
            const currentDate = new Date(uniqueFinishedDates[i]);
            const previousDate = new Date(uniqueFinishedDates[i - 1]);
            const differenceInDays = (currentDate - previousDate) / (1000 * 3600 * 24);

            if (differenceInDays === 1) {
                consecutiveDays++;
                if (consecutiveDays >= 10 && !currentBadges.includes('Legend of Dedication')) {
                    const badgeDoc = await db.collection('Badges').doc('Legend of Dedication').get();
                    if (badgeDoc.exists) {
                        Badges.push(badgeDoc.data().Name);
                    }
                } else if (consecutiveDays >= 5 && !currentBadges.includes('Consistency Master')) {
                    const badgeDoc = await db.collection('Badges').doc('Consistency Master').get();
                    if (badgeDoc.exists) {
                        Badges.push(badgeDoc.data().Name);
                    }                
                } else if (consecutiveDays >= 3 && !currentBadges.includes('Streak Champion')) {
                    const badgeDoc = await db.collection('Badges').doc('Streak Champion').get();
                    if (badgeDoc.exists) {
                        Badges.push(badgeDoc.data().Name);
                    } 
                }
            } else {
                consecutiveDays = 1;
            }
        }


            // Check and add 'holiday' badge
            if (isWeekend(finishedTime) && !currentBadges.includes('Holiday Hero')) {
                const badgeDoc = await db.collection('Badges').doc('holiday').get();
                if (badgeDoc.exists) {
                    Badges.push(badgeDoc.data().Name);
                }
            }

            if (volunteerRequests.length > 50 && !currentBadges.includes('bronze')) {
                const badgeDoc = await db.collection('Badges').doc('bronze').get();
                if (badgeDoc.exists) {
                    Badges.push(badgeDoc.data().Name);
                }
            }

            if (volunteerRequests.length > 100 && !currentBadges.includes('silver')) {
                const badgeDoc = await db.collection('Badges').doc('silver').get();
                if (badgeDoc.exists) {
                    Badges.push(badgeDoc.data().Name);
                }
            }

            if (volunteerRequests.length > 150 && !currentBadges.includes('gold')) {
                const badgeDoc = await db.collection('Badges').doc('gold').get();
                if (badgeDoc.exists) {
                    Badges.push(badgeDoc.data().Name);
                }
            }

            if (Badges.length > 0) {
                await addBadgeToVolunteer(volunteerId, Badges);
            }
        }

            // Update points in Requests collection
            await db.collection('Requests').doc(requestId).update({ VolunteerPoints: totalPoints });

            // Update points in Volunteers collection
            await addPointsToVolunteer(volunteerId, totalPoints);

        res.status(200).send({ message: 'Points and Badges updated successfully', Points: totalPoints, Badges });
    } catch (error) {
        console.error('Error in updating points and Badges', error);
        res.status(500).send({ error: 'Server error' });
    }
});

// Auxiliar functions 
async function getVolunteerRequests(volunteerId) {
    const requestsSnapshot = await db.collection('Requests').where('VolunteerID', '==', volunteerId).get();
    return requestsSnapshot.docs.map(doc => doc.data());
}

async function addPointsToVolunteer(volunteerId, Points) {
    const volunteerRef = db.collection('Volunteers').doc(volunteerId);
    const volunteerDoc = await volunteerRef.get();
    if (volunteerDoc.exists) {
        const currentPoints = volunteerDoc.data().Points || 0;
        await volunteerRef.update({ Points: currentPoints + Points });
    }
}

async function addBadgeToVolunteer(volunteerId, Badges) {
    const volunteerRef = db.collection('Volunteers').doc(volunteerId);
    const volunteerDoc = await volunteerRef.get();
    if (volunteerDoc.exists) {
        const currentBadges = volunteerDoc.data().Badges || [];
        const updatedBadges = [...new Set([...currentBadges, ...Badges])];
        await volunteerRef.update({ Badges: updatedBadges });
    }
}


const { DateTime } = require('luxon');

/**
 * @swagger
 * /volunteer/finished_request/{requestId}:
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
 *                 UserName:
 *                   type: string
 *                   description: The name of the user who left the review
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
            return res.status(200).send({ message: 'Waiting for the user to finish the request' });
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

        // Fetch the username from the Users collection using the UserID from the requestData
        const userId = requestData.UserID;
        let userName = 'Unknown';
        if (userId) {
            try {
                const userSnapshot = await db.collection('Users').doc(userId).get();
                userName = userSnapshot.exists ? userSnapshot.data().Name : 'Unknown';
            } catch (error) {
                console.error('Error fetching user data:', error.message);
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
            UserName: userName,
            Review: reviewData
        });

    } catch (error) {
        console.error('Error fetching finished request details', error);
        res.status(500).send({ error: 'Server error' });
    }
});



/**
 * @swagger
 * /volunteer/reviews/{volunteerId}:
 *   get:
 *     summary: Get all reviews for a volunteer
 *     tags: [Profile]
 *     parameters:
 *       - in: path
 *         name: volunteerId
 *         required: true
 *         description: The ID of the volunteer to get reviews for
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: A list of reviews for the volunteer
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   UserName:
 *                     type: string
 *                     description: The name of the user who gave the review
 *                   Feedback:
 *                     type: string
 *                     description: The feedback given by the user
 *                   Rating:
 *                     type: number
 *                     description: The rating given by the user
 *                   RequestID:
 *                     type: string
 *                     description: The ID of the request associated with the review
 *                   RequestDate:
 *                     type: string
 *                     description: The date (day, month, year) when the associated request was made
 *       400:
 *         description: Invalid volunteer ID
 *       404:
 *         description: No reviews found for this volunteer
 *       500:
 *         description: Server error
 */



// GET ALL REVIEWS FOR A VOLUNTEER
router.get('/reviews', authenticateToken, async (req, res) => {
//router.get('/reviews/:volunteerId', async (req, res) => {
    try {
        //const volunteerId = req.params.volunteerId;
        const volunteerId = req.volunteer.VolunteerId;
        if (!volunteerId) {
            return res.status(400).send({ error: 'Invalid volunteerId' });
        }

        // Fetch reviews for the specified volunteer
        const reviewsSnapshot = await db.collection('Reviews')
            .where('VolunteerID', '==', volunteerId)
            .get();

        if (reviewsSnapshot.empty) {
            return res.status(404).send({ error: 'No reviews found for this volunteer' });
        }

        const reviews = [];
        for (const reviewDoc of reviewsSnapshot.docs) {
            const reviewData = reviewDoc.data();
            const { UserID, Feedback, Rating, RequestID } = reviewData;

            // Fetch user name based on UserID
            const userRef = db.collection('Users').doc(UserID);
            const userSnapshot = await userRef.get();
            let userName = 'Unknown';
            if (userSnapshot.exists) {
                const userData = userSnapshot.data();
                userName = userData.Name || 'Unknown'; // Adjust as per the field name in Users collection
            }

            // Fetch the corresponding request to get the Timestamp
            const requestRef = db.collection('Requests').doc(RequestID);
            const requestSnapshot = await requestRef.get();
            let requestDate = 'Unknown';
            if (requestSnapshot.exists) {
                const requestData = requestSnapshot.data();
                const timestamp = new Date(requestData.Timestamp._seconds * 1000); // Convert Firestore timestamp to JS date

                // Format the date in English (US)
                const day = timestamp.getDate();
                const month = timestamp.toLocaleString('en-US', { month: 'long' }); // Ensure month is in English
                const year = timestamp.getFullYear();
                requestDate = `${day} ${month} ${year}`;
            }

            reviews.push({
                UserName: userName,
                Feedback: Feedback,
                Rating: Rating,
                RequestID: RequestID,
                RequestDate: requestDate // Include the RequestDate in the response
            });
        }

        // Return the list of reviews with user names and request dates
        return res.status(200).send(reviews);
    } catch (error) {
        console.error('Error in getting reviews for volunteer', error);
        return res.status(500).send({ error: 'Server error' });
    }
});



/**
 * @swagger
 * /volunteer/profile/{volunteerId}:
 *   get:
 *     summary: Get volunteer's profile information and average rating
 *     tags: [Profile]
 *     parameters:
 *       - in: path
 *         name: volunteerId
 *         required: true
 *         description: The ID of the volunteer to fetch profile information
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Volunteer's profile information and average rating retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 Email:
 *                   type: string
 *                   description: The email of the volunteer
 *                 Location:
 *                   type: object
 *                   properties:
 *                     latitude:
 *                       type: number
 *                       description: Latitude of the volunteer's location
 *                     longitude:
 *                       type: number
 *                       description: Longitude of the volunteer's location
 *                 Name:
 *                   type: string
 *                   description: The name of the volunteer
 *                 PhoneContact:
 *                   type: string
 *                   description: The phone contact of the volunteer
 *                 averageRating:
 *                   type: number
 *                   description: The average rating of the volunteer
 *                 Points:
 *                   type: number
 *                   description: The total points of the volunteer
 *                 Badges:
 *                   type: array
 *                   items:
 *                     type: string
 *                     description: List of badges the volunteer has
 *       400:
 *         description: Invalid volunteerId
 *       404:
 *         description: Volunteer not found
 *       500:
 *         description: Server error
 */


//SEE VOLUNTEER INFORMATIONS (EMAIL, NAME, PHONECONTACT) + AVERAGE RATING + BADGES + POINTS
router.get('/profile', authenticateToken, async (req, res) => {
//router.get('/profile/:volunteerId', async (req, res) => {
    try {
        const volunteerId = req.volunteer.VolunteerId;
        //const volunteerId = req.params.volunteerId;
        if (!volunteerId) {
            return res.status(400).send({ error: 'Invalid volunteerId' });
        }

        const volunteerRef = db.collection('Volunteers').doc(volunteerId);
        const volunteerDoc = await volunteerRef.get();
        if (!volunteerDoc.exists) {
            return res.status(404).send({ error: 'This email has no account, please go to signup' });
        }

        const volunteerData = volunteerDoc.data();

        // Search reviews
        const reviewsRef = db.collection('Reviews');
        const reviewsSnapshot = await reviewsRef.where('VolunteerID', '==', volunteerId).get();

        let totalRating = 0;
        let reviewCount = 0;

        if (!reviewsSnapshot.empty) {
            reviewsSnapshot.forEach(review => {
                const reviewData = review.data();
                totalRating += reviewData.Rating;
                reviewCount++;
            });

            const averageRating = totalRating / reviewCount;

            // update document with average rating 
            await volunteerRef.update({ averageRating });

            volunteerData.averageRating = averageRating;
        } else {
            // If there are no reviews for the volunteer
            volunteerData.averageRating = 0;
        }

        // Add the reviewCount to the volunteer data
        volunteerData.reviewCount = reviewCount;

        const { Password, ...volunteerDocWithoutPassword } = volunteerData;

        res.status(200).send(volunteerDocWithoutPassword);

    } catch (error) {
        console.error('Error in finding volunteer or reviews:', error);
        res.status(500).send({ error: 'Server error' });
    }
});



/**
 * @swagger
 * /volunteer/updateProfile/{volunteerId}:
 *   patch:
 *     summary: Update name and phone contact
 *     tags: [Profile]
 *     parameters:
 *       - in: path
 *         name: volunteerId
 *         required: true
 *         description: The ID of the volunteer to update
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
 *                 description: The new name of the volunteer
 *               PhoneContact:
 *                 type: string
 *                 pattern: ^\d+$  
 *                 description: The new phone contact of the volunteer
 *     responses:
 *       200:
 *         description: User data updated successfully
 *       400:
 *         description: Invalid volunteer ID or phone number
 *       500:
 *         description: Server error
 */

//UPDATE VOLUNTEER NAME AND PHONE CONTACT
router.patch('/updateProfile', authenticateToken, async (req, res) => {
    try {
        const volunteerId = req.volunteer.VolunteerId;
        if (!volunteerId) {
            return res.status(400).send({ error: 'Invalid volunteerId' });
        }
        const { Name, PhoneContact } = req.body;
        const updateFields = {};
        
        if (Name) updateFields.Name = Name;
        
        if (PhoneContact) {
            // Verfies if the phone contact contains only digits 
            if (!isValidPhoneNumber(PhoneContact)) {
                return res.status(400).send({ error: 'Invalid phone number format.' });
            }

            // Verifies if phone contact already exists in tha database 
            const existingVolunteersWithPhone = await db.collection('Volunteers')
            .where('PhoneContact', '==', PhoneContact)
            .get();
            let phoneExists = false;
            existingVolunteersWithPhone.forEach(doc => {
                if (doc.id !== volunteerId) {
                    phoneExists = true;
                }
            });

            if (phoneExists) {
                return res.status(400).send({ error: 'Phone number already exists for another volunteer.' });
            }

            updateFields.PhoneContact = PhoneContact;
        }

        const volunteerRef = db.collection('Volunteers').doc(volunteerId);
        await volunteerRef.update(updateFields);

        res.status(200).send({ message: 'Volunteer data updated successfully' });
    } catch (error) {
        console.error('Error in updating information', error);
        res.status(500).send({ error: 'Server error' });
    }
});


/**
 * @swagger
 * /volunteer/updatePassword/{volunteerId}:
 *   patch:
 *     summary: Update password
 *     tags: [Profile]
 *     parameters:
 *       - in: path
 *         name: volunteerId
 *         required: true
 *         description: The ID of the volunteer to update
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
 *         description: Invalid volunteer ID or password format
 *       500:
 *         description: Server error
 */

//UPDATE PASSWORD
router.patch('/updatePassword', authenticateToken, async (req, res) => {
    try {
        const volunteerId = req.volunteer.VolunteerId;
        console.log('Decoded VolunteerID from token:', volunteerId);

        if (!volunteerId) {
            return res.status(400).send({ error: 'Invalid volunteerId' });
        }

        const { newPassword, confirmNewPassword } = req.body;

        if (!newPassword || !confirmNewPassword) {
            return res.status(400).send({ error: 'Both password fields are required' });
        }

        if (!comparePasswords(newPassword, confirmNewPassword)) {
            return res.status(400).send({ error: 'Passwords do not match' });
        }

        const volunteerDoc = await db.collection('Volunteers').doc(volunteerId).get();
        if (!volunteerDoc.exists) {
            return res.status(404).send({ error: 'Volunteer not found' });
        }

        const volunteerData = volunteerDoc.data();

        // Verifies if the new password matches the old one 
        const passwordMatch = await bcrypt.compare(newPassword, volunteerData.Password);
        if (passwordMatch) {
            return res.status(400).send({ error: 'New password cannot be the same as the old password' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.collection('Volunteers').doc(volunteerId).update({ Password: hashedPassword });

        return res.status(200).send({ message: 'Password updated successfully' });

    } catch (error) {
        console.error('Error in updating password', error);
        return res.status(500).send({ error: 'Server error' });
    }
});


/**
 * @swagger
 * /volunteer/delete:
 *   delete:
 *     summary: Delete a volunteer by ID
 *     tags: [Profile]
 *     parameters:
 *       - in: query
 *         name: volunteerID
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the volunteer to be deleted
 *     responses:
 *       200:
 *         description: Volunteer deleted successfully
 *       400:
 *         description: Invalid volunteer ID
 *       404:
 *         description: Volunteer not found
 *       500:
 *         description: Server error
 */


// DELETE VOLUNTEER (volunteerID)
router.delete('/delete', authenticateToken, async (req, res) => {
    try {
        //const { volunteerID } = req.query;
        const volunteerID = req.volunteer.VolunteerId;

        if (!volunteerID) {
            return res.status(400).send({ error: 'Invalid volunteer ID' });
        }

        const volunteerRef = db.collection('Volunteers').doc(volunteerID);
        const volunteerDoc = await volunteerRef.get();

        if (!volunteerDoc.exists) {
            return res.status(404).send({ error: 'Volunteer not found' });
        }

        await volunteerRef.delete();

        res.status(200).send({ message: 'Volunteer deleted successfully' });
    } catch (error) {
        console.error('Error occurred during volunteer deletion:', error);
        res.status(500).send({ error: 'Server error' });
    }
});



/**
 * @swagger
 * /volunteer/history/{volunteerId}:
 *   get:
 *     summary: Get volunteer's request history ordered by most recent
 *     tags: [Requests]
 *     parameters:
 *       - in: path
 *         name: volunteerId
 *         required: true
 *         description: The ID of the volunteer to fetch request history
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Volunteer's request history retrieved successfully, ordered by most recent
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               description: Array of requests ordered by most recent
 *               items:
 *                 type: object
 *                 properties:
 *                   RequestID:
 *                     type: string
 *                     description: The ID of the request
 *                   Status:
 *                     type: string
 *                     description: The status of the request
 *                   Timestamp:
 *                     type: string
 *                     format: date-time
 *                     description: The timestamp of the request
 *                   UserName:
 *                     type: string
 *                     description: The name of the user assigned to the request
 *       400:
 *         description: Invalid volunteerId
 *       404:
 *         description: No requests found for the volunteer
 *       500:
 *         description: Server error
 */


// REQUEST HISTORY (LOCATION, TIMESTAMP, USER, STATUS, DURATION OF EACH REQUEST) - Organized by Month - OpenStreetMap Nominatim API
//router.get('/history/:volunteerId', async (req, res) => {
    router.get('/history', authenticateToken, async (req, res) => {
        try {
            //const volunteerId = req.params.volunteerId;
            const volunteerId = req.volunteer.VolunteerId;
            if (!volunteerId) {
                return res.status(400).send({ error: 'Invalid volunteerId' });
            }
    
            const volunteerRequestsRef = db.collection('Requests').where('VolunteerID', '==', volunteerId);
            const volunteerRequestsSnapshot = await volunteerRequestsRef.get();
    
            if (volunteerRequestsSnapshot.empty) {
                return res.status(404).send({ message: 'No requests found for the volunteer' });
            }
    
            const requests = [];
    
            for (const doc of volunteerRequestsSnapshot.docs) {
                const request = doc.data();
    
                // Fetch user information
                const userSnapshot = await db.collection('Users').doc(request.UserID).get();
                request.UserName = userSnapshot.exists ? userSnapshot.data().Name : 'Unknown';
    
    
                // Format the timestamp and extract the month and year in English and uppercase
                const formattedTimestamp = DateTime.fromMillis(request.Timestamp._seconds * 1000).setZone('Europe/Lisbon').toFormat('EEE, dd MMM yyyy HH:mm:ss');
    
                // Create the request object
                const requestObject = {
                    RequestID: doc.id, 
                    Status: request.Status,
                    Timestamp: formattedTimestamp,
                    UserName: request.UserName
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



/**
 * @swagger
 * /volunteer/logout/{userId}:
 *   post:
 *     summary: Logout a volunteer
 *     tags: [Authentication]
 *     parameters:
 *       - in: path
 *         name: volunteerId
 *         required: true
 *         description: ID of the volunteer to log out
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Logged out successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Logged out successfully.
 *       400:
 *         description: Bad Request if userId is invalid
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid userId
 *       404:
 *         description: Not Found if volunteerId does not exist
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Volunteer not found
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Server error
 */



// LOGOUT
router.post('/logout', authenticateToken, async (req, res) => {
    const volunteerId = req.volunteer.VolunteerId; 

        const requestsSnapshot = await db.collection('Requests')
            .where('VolunteerID', '==', volunteerId)
            .where('Status', '==', 'accepted')
            .get();

        const batch = db.batch(); 
        requestsSnapshot.forEach(doc => {
            const requestRef = db.collection('Requests').doc(doc.id);
            batch.update(requestRef, { Status: 'cancelled' });
        });

        await batch.commit();
    loggedInVolunteers.delete(volunteerId); 
    console.log(loggedInVolunteers)
    res.status(200).send({ message: 'Logged out successfully.' });
});


module.exports = router;
