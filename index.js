const express = require('express');
const { FieldValue } = require('firebase-admin/firestore');
const cors = require('cors');
const admin = require('firebase-admin');
const session = require('express-session');
const passport = require('passport');
const swaggerjsdoc = require('swagger-jsdoc');
const swaggerui = require('swagger-ui-express');
const fs = require('fs');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

const { db } = require('./database/firebase.js');

// Routes
const userRoute = require('./routes/user.js');
const volunteerRoute = require('./routes/volunteer.js');

// Middleware
app.use(cors());
app.use(express.json());
app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// API routes
app.use('/user', userRoute);
app.use('/volunteer', volunteerRoute);

// Swagger setup
const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "HELPER",
      description: "Mobile App"
    },
    servers: [
      {
        url: "http://localhost:3000",
      },
    ],
  },
  apis: ["./routes/*.js"],
};

const specs = swaggerjsdoc(options);
app.use('/api-docs', swaggerui.serve, swaggerui.setup(specs));

// API endpoints
app.get('/users', async (req, res) => {
  try {
    const UserRef = db.collection('Users');
    const users = await UserRef.get();
    if (users.empty) {
      return res.status(400).send({ error: 'No users found' });
    }
    const usersList = [];
    users.forEach(doc => {
      const user = doc.data();
      user.id = doc.id;
      usersList.push(user);
    });
    res.status(200).send(usersList);
  } catch (error) {
    console.error('Error in finding users', error);
    res.status(500).send({ error: 'Server error' });
  }
});

// Add more API endpoints as needed

app.listen(port, () => {
  console.log(`Server has started on port: ${port}`);
});







/*
const express = require('express')
const { FieldValue } = require('firebase-admin/firestore')

//do código da ju
const cors = require('cors');

const admin = require('firebase-admin')


const app = express()
const port = 3000

const { db } = require('./database/firebase.js')
const session = require('express-session');

const passport = require('passport');


const swaggerjsdoc = require ("swagger-jsdoc");
const swaggerSpec = require('swagger-spec'); 
const swaggerui = require ("swagger-ui-express");
const swaggerparser = require ("swagger-parser");

require('dotenv').config();

//ROUTES
const userRoute = require ('./routes/user.js');
const volunteerRoute = require ('./routes/volunteer.js');

//do código da ju
app.use(cors());

app.use(express.json())


app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false
  }));

app.use(passport.initialize());
app.use(passport.session());


app.use('/user', userRoute); 
app.use('/volunteer', volunteerRoute); 




// Página Inicial (Escolher User ou Volunteer)
//router.get('/', (req, res) => {
//  });

  
//-----------------------------------------------------------------------------------------------------------------------
//métodos com a base de dados

app.get('/users', async (req, res) => {
    try {
        const UserRef = db.collection('Users')
        const users = await UserRef.get()
        if (users.empty) {
            return res.status(400).send({ error: 'No users found' })
        }
        
        const usersList = [];
        users.forEach(doc => {
            const user = doc.data();
            user.id = doc.id;
            usersList.push(user);
        });

        res.status(200).send(usersList);
    } catch (error) {
        console.error('Error in finding users', error);
        res.status(500).send({ error: 'Server error' });
    }
})

app.get('/volunteers', async (req, res) => {
    try {
        const VolunteerRef = db.collection('Volunteers')
        const volunteers = await VolunteerRef.get()
        if (volunteers.empty) {
            return res.status(400).send({ error: 'No volunteers found' })
        }
        
        const volunteersList = [];
        volunteers.forEach(doc => {
            const volunteer = doc.data();
            volunteer.id = doc.id;
            volunteersList.push(volunteer);
        });

        res.status(200).send(volunteersList);
    } catch (error) {
        console.error('Error in finding volunteers', error);
        res.status(500).send({ error: 'Server error' });
    }
})

app.get('/requests', async (req, res) => {
    try {
        const RequestRef = db.collection('Requests')
        const requests = await RequestRef.get()
        if (requests.empty) {
            return res.status(400).send({ error: 'No requests found' })
        }
        
        const requestsList = [];
        requests.forEach(doc => {
            const request = doc.data();
            request.id = doc.id;
            requestsList.push(request);
        });

        res.status(200).send(requestsList);
    } catch (error) {
        console.error('Error in finding requests', error);
        res.status(500).send({ error: 'Server error' });
    }
})




app.post('/addUser', async (req, res) => {
    try {
        const { Name, Email, Password, PhoneContact } = req.body
        const UserRef = db.collection('Users').add({
            Name: Name,
            Password: Password,
            Email: Email,
            PhoneContact: PhoneContact,
        })
        res.status(200).send({ message: 'User added successfuly.', UserID: UserRef.id });
    } catch (error) {
        console.error('User not added', error);
        res.status(500).send({ error: 'Server error' });
    }
    
});


app.post('/addVolunteer', async (req, res) => {
    try {
        const { Name, Email, Password, PhoneContact } = req.body
        const VolunteerRef = db.collection('Volunteers').add({
            Name: Name,
            Password: Password,
            Email: Email,
            PhoneContact: PhoneContact,

        })
        res.status(200).send({ message: 'Volunteer added successfuly.', VolunteerID: VolunteerRef.id });
    } catch (error) {
        console.error('Volunteer not added', error);
        res.status(500).send({ error: 'Server error' });
    }
    
})

app.post('/addRequest', async (req, res) => {
    try {
        const { UserID, Timestamp, Status, Location, VolunteerID } = req.body
        const requestLocation = new admin.firestore.GeoPoint(Location.latitude, Location.longitude);
        const timestamp = admin.firestore.FieldValue.serverTimestamp();
        const RequestRef = db.collection('Requests').add({
            UserID: UserID,
            Timestamp: timestamp,
            Status: Status,
            Location: requestLocation,
            VolunteerID: VolunteerID,
        })
        res.status(200).send({ message: 'Request added successfuly.', RequestID: RequestRef.id });
    } catch (error) {
        console.error('Request not added', error);
        res.status(500).send({ error: 'Server error' });
    }
    
})


app.post('/addVolunteerEvaluation', async (req, res) => {
    try {
        const { Feedback, Rating, UserID, VolunteerID } = req.body
        const VolunteerEvaluationRef = db.collection('Volunteer Evaluation').add({
            Feedback: Feedback,
            UserID: UserID,
            Rating: Rating,
            VolunteerID: VolunteerID,
        })
        res.status(200).send({ message: 'Evaluation added successfuly.', VolunteerEvaluationID: VolunteerEvaluationRef.id });
    } catch (error) {
        console.error('Evaluation not added', error);
        res.status(500).send({ error: 'Server error' });
    }
    
})

//----------------------------------------------------------------------------------------------------------

const options = {
    definition: {
        openapi: "3.0.0",
        info: {
            title: "HELPER",
            description: "Mobile App"
        },
        servers: [
            {
                url: "http://localhost:3000",
            },
        ],
    },
    apis: ["./routes/*.js"],
};


const spacs = swaggerjsdoc(options)
app.use(
    "/api-docs",
    swaggerui.serve,
    swaggerui.setup(spacs)
)


const specs = swaggerjsdoc(options);

app.use('/api-docs', swaggerui.serve, swaggerui.setup(specs));


module.exports = specs;

const fs = require('fs');

fs.writeFileSync('./openapi.json', JSON.stringify(specs, null, 2));



app.listen(port, '0.0.0.0', () => console.log(`Server has started on port: ${port}`))


*/