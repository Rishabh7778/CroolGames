
require('dotenv').config();
const express = require("express")
const path = require('path')
const Games = require('./models/games')
const catchasync = require('./utils/catchasync')
const ExpressError = require('./utils/expresserror')
const Review = require('./models/review.js')
const mongoose = require('mongoose');
const mo = require('method-override')
const session = require('express-session')
const MongoStore=require('connect-mongo')
const flash = require('connect-flash')
const { Gschema, Rschema } = require('./schema.js')
const ejsMate = require('ejs-mate')
const passport = require('passport')
const localStorage = require('passport-local').Strategy
const User = require('./models/user.js')
const { isloged, storeR, isAuthor, isReview, isAdmin } = require('./views/middleware.js')
const { initializeApp } = require("firebase/app");
const { getStorage, ref, getDownloadURL, uploadBytesResumable, deleteObject, getMetadata } = require("firebase/storage");
const multer = require("multer");
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

// Inside your route handler function

initializeApp({
    apiKey: process.env.FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN,
    projectId: process.env.FIREBASE_PROJECT_ID,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.FIREBASE_APP_ID,
    measurementId: process.env.FIREBASE_MEASUREMENT_ID
})
const admin = require('firebase-admin');
const serviceAccount = {
    "type": process.env.FIREBASE_TYPE,
    "project_id": process.env.FIREBASE_PROJECT_ID,
    "private_key_id": process.env.FIREBASE_PRIVATE_KEY_ID,
    "private_key": process.env.FIREBASE_PRIVATE_KEY,
    "client_email": process.env.FIREBASE_CLIENT_EMAIL,
    "client_id": process.env.FIREBASE_CLIENT_ID,
    "auth_uri": process.env.FIREBASE_AUTH_URI,
    "token_uri": process.env.FIREBASE_TOKEN_URI,
    "auth_provider_x509_cert_url": process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
    "client_x509_cert_url": process.env.FIREBASE_CLIENT_X509_CERT_URL,
    "universe_domain": process.env.FIREBASE_UNIVERSE_DOMAIN
};

// Initialize Firebase Admin SDK
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET
});
const bucket = admin.storage().bucket(process.env.FIREBASE_STORAGE_BUCKET);
const storage = getStorage();
const upload = multer({ storage: multer.memoryStorage() });


const mongoSantize = require('express-mongo-sanitize');
const helmet = require('helmet');

//mongo connection

const DB=process.env.DB_URL
mongoose.connect(DB)
    .then(() => {
        console.log("Connected to MongoDB");
    })
    .catch((error) => {
        console.error("Error connecting to MongoDB:", error);
    });
ap = express();
ap.engine('ejs', ejsMate)
ap.set('view engine', 'ejs')
ap.set('views', path.join(__dirname, '/views'))
ap.use(express.static("public"));
ap.use(mongoSantize());
ap.use(express.urlencoded({ extended: true }))
ap.use(mo("_method"))
//flash


const store = MongoStore.create({
    mongoUrl: DB,
    crypto: {
        secret: 'secretherebaba'
    },
    touchAfter: 24 * 60 * 60
});
store.on('error', function (e) {
    console.error('Session store error:', e);
});
const sessionconfig = {
    store:store,
    name: 'Session',
    secret: 'secretherebaba',
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        // secure:true,
        expires: Date.now() + 1000 * 60 * 60 * 24 * 7,
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}
ap.use(session(sessionconfig))
ap.use(flash())
const scriptSrcUrls = [
    "https://cdn.jsdelivr.net",
    "https://code.jquery.com/",
    "https://stackpath.bootstrapcdn.com/"];
const styleSrcUrls = [
    "'self'",
    "https://cdn.jsdelivr.net",
    "https://code.jquery.com/"
];

const connectSrcUrls = [];
const fontSrcUrls = [];
const imgSrcUrls = [
    "'self'", "blob:", "data:",
    "https://images.unsplash.com/",
    "https://plus.unsplash.com/",
    "https://firebasestorage.googleapis.com/"];

ap.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: [],
        connectSrc: ["'self'", ...connectSrcUrls],
        scriptSrc: ["'unsafe-inline'", "'self'", ...scriptSrcUrls],
        styleSrc: ["'self'", ...styleSrcUrls],
        workerSrc: ["'self'", "blob:"],
        objectSrc: [],
        imgSrc: imgSrcUrls,
        fontSrc: ["'self'", ...fontSrcUrls],
        mediaSrc: ["'self'", "http://localhost:3000", "https://storage.googleapis.com"]
    }
}));

ap.use(passport.initialize());
ap.use(passport.session());
passport.use(new localStorage(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());


ap.use(isAdmin);  
ap.use((req, res, next) => {
    res.locals.currentUser = req.user;
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    res.locals.Admin = req.user ? req.user.isAdmin : false;
    next();
});


//middleware
const validateSchema = (req, res, next) => {
    const { error } = Gschema.validate(req.body)
    if (error) {
        console.error(error); 
        const msg = error.details.map(el => el.message).join(',')
        throw new ExpressError(msg, 400)
    }
    else {
        next();
    }
}

const reviewSchema = (req, res, next) => {
    const { error } = Rschema.validate(req.body)
    if (error) {
        const msg = error.details.map(el => el.message).join(',')
        throw new ExpressError(msg, 400)
    }
    else {
        next();
    }
}

//games routes
ap.get("/", async (req, res) => {
    try {
        // Get the search query from the request parameters
        const searchQuery = req.query.title || '';
        // Use a regular expression to make the search case-insensitive
        const regex = new RegExp(searchQuery, 'i');
        const gam = await Games.find({ title: regex });

        res.render('home', { gam, searchQuery });
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});
ap.get("/games", async (req, res) => {
    try {
        // Get the search query from the request parameters
        const searchQuery = req.query.title || '';
        // Get the category from the request query
        const category = req.query.category || ''; // Default to empty string if no category provided

        // Use a regular expression to make the search case-insensitive for both title and category
        const titleRegex = new RegExp(searchQuery, 'i');
        const categoryRegex = new RegExp(category, 'i');

        // Find games that match both the title and category
        const gam = await Games.find({ title: titleRegex, category: categoryRegex });

        res.render('home', { gam, category, searchQuery });
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});


ap.get('/games/new', isloged, isAdmin, async (req, res) => {
    res.render('new')
})
ap.post('/games',
    upload.fields([{ name: 'image' }, { name: 'gameFile' }]),
    validateSchema,
    catchasync(async (req, res, next) => {
        try {
            // Check if files are uploaded
            if (!req.files || !req.files['image'] || !req.files['gameFile']) {
                throw new Error('No files uploaded');
            }

            // Extract the relevant data from the request
            const { title, description, category } = req.body.games;
            console.log("RRR:", req.body.games);
            const imageFiles = req.files['image'];
            const gameFile = req.files['gameFile'][0]; // Assuming only one game file is uploaded

            // Replace the filename with the game ID
            const gameId = uuidv4();
            const newGameFileName = gameId + '.' + gameFile.originalname.split('.').pop(); // New filename with game ID

            // Upload image files to Firebase Storage
            const imageUploadPromises = imageFiles.map(async (file) => {
                const storageRef = ref(storage, `files/${file.originalname}`);
                const metadata = { contentType: file.mimetype };
                const snapshot = await uploadBytesResumable(storageRef, file.buffer, metadata);
                return getDownloadURL(snapshot.ref);
            });

            // Wait for all image uploads to complete
            const imageUrls = await Promise.all(imageUploadPromises);

            // Create an array of image objects with their respective URLs
            const imageObjects = imageUrls.map(url => ({ url }));


            // Upload game file to Firebase Storage with the new filename
            const gameStorageRef = ref(storage, `files/${newGameFileName}`);
            const gameMetadata = { contentType: gameFile.mimetype };
            const gameSnapshot = await uploadBytesResumable(gameStorageRef, gameFile.buffer, gameMetadata);
            const gameFileDownloadUrl = await getDownloadURL(gameSnapshot.ref);

            // Create a new game document with the uploaded image URLs
            const newGame = new Games({
                title: title,
                description: description,
                image: imageObjects, // Assign an array of image objects
                category: category,
                author: req.user._id,
                gameFile: {  // Save the game file URL in the gameFile field
                    url: gameFileDownloadUrl,
                    filename: newGameFileName // Optionally save the filename if needed
                },
                gameId: gameId // Add the game file URL to the game document
            });

            // Save the new game object to the database
            await newGame.save();

            // Redirect to the newly created game
            req.flash('success', 'Successfully Uploaded a Game');
            res.redirect(`/games/${newGame._id}`);
        } catch (error) {
            console.error(error);
            // Handle error appropriately
            req.flash('error', 'Failed to upload the game', error.message);
            res.redirect('/games'); // Redirect to a proper error handling route or page
        }
    })
);


ap.get('/games/:id', async (req, res) => {
    const g = await Games.findById(req.params.id).populate({
        path: 'reviews',
        populate: {
            path: 'author'
        }
    }).populate('author')
    console.log(g);
    if (!g) {
        req.flash('error', 'Cannot find that campground')
        return res.redirect('/')
    }
    res.render('show', { g })
})

ap.get('/games/:id/download', async (req, res) => {
    try {
        const g = req.params.id;

        // Retrieve the game document from the database
        const game = await Games.findOne({ gameId: g });
        console.log("Game ID :     ", game);
        if (!game) {
            return res.status(404).send('Game not found');
        }

        // Construct the file path based on the UUID and any desired folder structure
        const filePath = `files/${g}.zip`;

        // Get a reference to the file in Firebase Storage
        const file = bucket.file(filePath);

        // Generate a signed URL for the file
        const options = {
            action: 'read',
            expires: Date.now() + 15 * 60 * 1000, // 15 minutes from now
        };
        const [signedUrl] = await file.getSignedUrl(options);

        // Redirect the user to the signed URL for download
        res.redirect(signedUrl);
    } catch (error) {
        console.error('Error downloading file:', error);
        res.status(500).send('Internal Server Error');
    }
});



ap.get('/games/:id/edit', isloged, isAuthor, async (req, res) => {
    const { id } = req.params;
    try {
        const g = await Games.findById(id);
        if (!g) {
            req.flash('error', 'Cannot find that game');
            return res.redirect('/games');
        }
        res.render('edit', { g });
    } catch (error) {
        req.flash('error', 'An error occurred');
        res.redirect('/games');
    }
});


ap.put('/games/:id',
    upload.fields([{ name: 'image' }, { name: 'gameFile' }]),
    isAdmin,
    validateSchema,
    catchasync(async (req, res, next) => {
        try {
            const { id } = req.params;
            // Find the game by ID
            let gs = await Games.findById(id);
            // Check if the game exists
            if (!gs) {
                req.flash('error', 'Game not found');
                return res.redirect('/games');
            }
            // Update game details
            gs.title = req.body.games.title;
            gs.description = req.body.games.description;
            gs.category = req.body.games.category;
            // Update images if any

            const imageFiles = req.files['image'];

            // Check if imageFiles is an array and it's not empty
            if (Array.isArray(imageFiles) && imageFiles.length > 0) {
                // Upload image files to Firebase Storage
                const imageUploadPromises = imageFiles.map(async (file) => {
                    const storageRef = ref(storage, `files/${file.originalname}`);
                    const metadata = { contentType: file.mimetype };
                    const snapshot = await uploadBytesResumable(storageRef, file.buffer, metadata);
                    return getDownloadURL(snapshot.ref);
                });

                // Wait for all image uploads to complete
                const imageUrls = await Promise.all(imageUploadPromises);
                // Create an array of image objects with their respective URLs
                const newImages = imageUrls.map(url => ({ url }));
                gs.image = gs.image.concat(newImages);
            } else {
                console.log("No image files found in the request.");
            }
            // console.log("GSSSS", gs);
            // Remove deleted images from Firebase Storage and MongoDB
            if (req.body.deleteImages && req.body.deleteImages.length > 0) {
                for (const url of req.body.deleteImages) {
                    // Delete image from Firebase Storage
                    const filenameWithDir = url.split('/').pop();
                    const filenameParts = filenameWithDir.split('%2F');
                    const filename = filenameParts.pop().split('?')[0];
                    const fileRef = ref(storage, 'files/' + filename);
                    await deleteObject(fileRef);
                }
                // Remove deleted image URLs from MongoDB
                console.log("Selected images for deletion:", req.body.deleteImages);
            
                // Remove 'files/' prefix from the URLs in deleteImages array
                const deleteImagesWithoutPrefix = req.body.deleteImages.map(url => url.replace('files/', ''));
            
                // Filter out the images that are not selected for deletion
                gs.image = gs.image.filter(image => {
                    // Check if the image URL without the prefix is included in the deleteImages array
                    const shouldRemove = deleteImagesWithoutPrefix.includes(image.url);
                    if (shouldRemove) {
                        console.log(`Deleting image with URL: ${image.url}`);
                        // Perform deletion process here (e.g., delete from Firebase Storage)
                        // Return false to filter out this image
                        return false;
                    } else {
                        console.log(`NOT WORK: ${image.url}`);
                        // Keep the image in the gs.image array
                        return true;
                    }
                });
            }
            
            // Save updated game details
            await gs.save();

            req.flash('success', 'Successfully Updated a Game');
            res.redirect(`/games/${gs._id}`);
        } catch (error) {
            console.error(error);
            req.flash('error', 'Failed to update the game', error.message);
            res.redirect(`/games/${req.params.id}`);
        }
    })
);


ap.delete('/games/:id', isAuthor, catchasync(async (req, res, next) => {
    const { id } = req.params;
    console.log("Game ID:", id);
    try {
        // Find the game by ID
        const game = await Games.findById(id);
        console.log("Game found:", game);

        if (!game) {
            throw new Error('Game not found');
        }

        // Delete associated images from Firebase Storage
        for (const image of game.image) {
            console.log("Deleting image:", image.url);
            const filePath = decodeURIComponent(new URL(image.url).pathname).split('/o/')[1]; // Extract the file path after '/o/'
            await admin.storage().bucket().file(filePath).delete();
            console.log(`Deleted image: ${image.url}`);
        }

        // Delete associated game file from Firebase Storage if it exists
        if (game.gameFile && game.gameFile !== '') {
            console.log("Deleting game file:", game.gameFile);
            const gameFilePath = decodeURIComponent(new URL(game.gameFile.url).pathname).split('/o/')[1]; // Extract the file path after '/o/'
            await admin.storage().bucket().file(gameFilePath).delete();
            console.log(`Deleted game file: ${game.gameFile}`);
        }

        // Delete associated reviews from the database
        console.log("Deleting reviews for game:", id);
        await Review.deleteMany({ game: id });
        console.log(`Deleted reviews for game with ID: ${id}`);

        // Delete the game from the database
        console.log("Deleting game from database:", id);
        await Games.findByIdAndDelete(id);
        console.log(`Deleted game with ID: ${id}`);

        req.flash('success', 'Successfully Deleted a Game');
        res.redirect('/');
    } catch (error) {
        console.error("Error occurred while deleting game:", error);
        req.flash('error', 'An error occurred');
        res.redirect(`/games/${id}`);
    }
}));

//Review routes
ap.post('/games/:id/review', reviewSchema, isloged, catchasync(async (req, res) => {
    const games = await Games.findById(req.params.id);
    const review = new Review(req.body.review);
    review.author = req.user._id;
    games.reviews.push((review));
    await review.save();
    await games.save();
    req.flash('success', 'Successfully Submited a Review')
    res.redirect(`/games/${games._id}`);
}))

ap.delete('/games/:id/reviews/:reviewid', isloged, catchasync(async (req, res) => {
    const { id, reviewid } = req.params;
    const currentUser = req.user; // Assuming user information is stored in req.user
    const game = await Games.findById(id);
    const review = await Review.findById(reviewid);

    // Check if the current user is an admin or the author of the review
    if (currentUser.isAdmin || (currentUser._id.toString() === review.author.toString())) {
        await Games.findByIdAndUpdate(id, { $pull: { reviews: reviewid } });
        await Review.findByIdAndDelete(reviewid);
        req.flash('success', 'Successfully Deleted a Review');
        res.redirect(`/games/${id}`);
    } else {
        req.flash('error', 'Unauthorized to delete this review');
        res.redirect(`/games/${id}`);
    }
}));

//register routes
ap.get('/register', (req, res, next) => {
    res.render('user/register');
})


ap.post('/register', async (req, res) => {
    console.log("Body :", req.body);
    const { username, email, password, isAdmin } = req.body;
    try {
        const newUser = new User({
            username: username,
            email: email,
            isAdmin: Boolean(isAdmin)
        });
        // Use passport-local-mongoose's register method to handle hashing
        await User.register(newUser, password);

        // Capture the registered user after registration
        const registeredUser = await User.findOne({ username: newUser.username });

        console.log('Registered user:', registeredUser);
        req.flash('success', 'Welcome to Yelp');
        res.redirect('/');
    } catch (err) {
        console.error('Registration error:', err);
        req.flash('error', err.message);
        res.redirect('/');
    }
});



//login routes
ap.get('/login', (req, res) => {
    res.render('user/login')
})
ap.post('/login', storeR, (req, res, next) => {
    // Logging to trace the values of request body variables
    console.log('Request body:', req.body);

    // Call the passport.authenticate function
    passport.authenticate('local', (err, user, info) => {
        // Log any error or info messages
        if (err) {
            console.error('Passport authentication error:', err);
            return next(err);
        }
        if (!user) {
            console.log('Authentication failed:', info.message);
            req.flash('error', info.message);
            return res.redirect('/login');
        }
        // If authentication is successful
        req.logIn(user, (err) => {
            if (err) {
                console.error('User login error:', err);
                return next(err);
            }
            console.log('User logged in:', user.username);
            req.flash('success', 'Hurray you are logged in');
            const redirectUrl = res.locals.returnTo || '/';
            return res.redirect(redirectUrl);
        });
    })(req, res, next);
});


//logout
ap.get('/logout', (req, res, next) => {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        req.flash('success', 'Goodbye!');
        res.redirect('/');
    });
});

//error handling
ap.all('*', (req, res, next) => {
    next(new ExpressError('Page Not Found', 404))
})
ap.use((err, req, res, next) => {
    const { statuscode = 500 } = err;
    if (!err.message) err.message = "OH SomeThing went Wrong";
    res.status(statuscode).render('error', { err });
})

ap.listen(3000, () => {
    console.log("Connected to 3000")
})