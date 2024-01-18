/**
 * These following codes is adapted from instructor Arron's 2537 examples and changes made by our team.
 * @author Arron_Ferguson (1537 instructor) and students from team BBY15: Anh Nguyen, Linh Nguyen, Vincent Lam and Dongwan_Kang.
 * @param {*} data user input
 */

"use strict";

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mysql = require("mysql2");
const app = express();
const fs = require("fs");
const {
    JSDOM
} = require('jsdom');
const multer = require("multer");

const key = process.env.JWT_KEY;
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({
    extended: true
}));

const connectionLocal = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
};

var connection = mysql.createPool(connectionLocal);
let port = 8000
app.listen(port, function () {});

// Separates the payload from the token
function parseToken(req) {
    const token = req.headers['authorization']?.split(' ')[1];
    const decoded = jwt.verify(token, key);
    return decoded;
}

// Checks to see if user is authenticated
app.get('/api/authenticate', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) return res.sendStatus(401);

    // Verify the token is valid
    jwt.verify(token, key, (err) => {
        if (err) return res.sendStatus(401);
    });    

    return res.sendStatus(200);
});

// Checks to see if user is an admin
app.get('/api/authorize', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) return res.sendStatus(401); // No token found

    // Verify the token is valid with the key
    jwt.verify(token, key, (err, decodedToken) => {
        if (err) return res.sendStatus(401); // Invalid token

        // Check if user is an admin
        if (!decodedToken.isAdmin) {
            return res.sendStatus(403); // Valid token but not an admin
        }
        return res.sendStatus(200); // User is an admin and authorized
    });
});

// Checks to see if user is authenticated and refreshes the token
app.post('/api/refesh-token', (req, res) => {
    // Get current token
    const oldToken = req.headers['authorization']?.split(' ')[1];

    // Verify the token is valid with the key and decode it
    jwt.verify(oldToken, key, (err, decodedPayload) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid Token' });
        }

        // Create new token with the same payload
        const newToken = jwt.sign(decodedPayload, MediaKeySession, { expiresIn: '30m' });

        // Send status 200 and the new token back to the client
        res.status(200).json({ token: newToken });
    });
});

// Checks to see if user is authenticated and refreshes the token
app.post('/api/refesh-authorize', (req, res) => {
    // Get current token
    const oldToken = req.headers['authorization']?.split(' ')[1];

    // Verify the token is valid and decode it
    jwt.verify(oldToken, key, (err, decodedPayload) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid Token' });
        }

        // Create new token with the same payload
        const newToken = jwt.sign(decodedPayload, MediaKeySession, { expiresIn: '30m' });

        // Check if user is an admin
        if (!decodedPayload.isAdmin) {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        // Send status 200 and the new token back to the client
        res.status(200).json({ token: newToken });
    });
});

//function needed for getting list of all users in user-list
app.get("/api/user-list", function (req, res) {
    let user_list_jsdom = new JSDOM(doc);
    res.setHeader("Content-Type", "text/html");

    connection.query(
        "SELECT * FROM BBY_15_User WHERE admin_role = 0",
        function (error, results, fields) {

            let user_list = `<thead><tr>
            <th class="id_header">ID</th>
            <th class="first_name_header">First Name</th>
            <th class="last_name_header">Last Name</th>
            <th class="email_header">Email</th>
            <th class="password_header">Password</th>
            <th class="admin_header">Role</th>
            <th class="delete_header">Delete</th>
            </tr></head>`;
            for (let i = 0; i < results.length; i++) {

                user_list += ("<tbody><tr><td class='id'>" + results[i].user_id +
                    "</td><td class='first_name'><div class='material-icons'>edit</div><span>" + results[i].first_name +
                    "</span></td><td class='last_name'><div class='material-icons'>edit</div><span>" + results[i].last_name +
                    "</span></td><td class='email'><div class='material-icons'>edit</div><span>" + results[i].email +
                    "</span></td><td class='password'><div class='material-icons'>edit</div><span>" + results[i].user_password +
                    "</span></td><td class='role'>" + "<button type='button' class='role_switch_to_admin'>Make Admin" +
                    "</button></td><td class='delete'>" + "<button type='button' class='deleteUser'>Delete" +
                    "</button></td></tr></tbody>"
                );
            }
            user_list_jsdom.window.document.getElementById("user-container").innerHTML = user_list;
            res.send(user_list_jsdom.serialize());
        }
    );
});

// function for getting all admins for admin-list
app.get("/api/admin-list", function (req, res) {
    let admin_list_jsdom = new JSDOM(doc);
    res.setHeader("Content-Type", "text/html");
    const userID = parseToken(req)?.userID;

    connection.query(
        "SELECT * FROM BBY_15_User WHERE admin_role = 1",
        function (error, results, fields) {

            let admin_list = `<thead><tr>
            <th class="id_header">ID</th>
            <th class="first_name_header">First Name</th>
            <th class="last_name_header">Last Name</th>
            <th class="email_header">Email</th>
            <th class="password_header">Password</th>
            <th class="admin_header">Role</th>
            <th class="delete_header">Delete</th>
            </tr></thead>`;
            for (let i = 0; i < results.length; i++) {
                if (userID != results[i]['user_id']) {
                    admin_list += ("<tr><td class='id'>" + results[i].user_id +
                        "</td><td class='first_name'><div class='material-icons'>edit</div><span>" + results[i].first_name +
                        "</span></td><td class='last_name'><div class='material-icons'>edit</div><span>" + results[i].last_name +
                        "</span></td><td class='email'><div class='material-icons'>edit</div><span>" + results[i].email +
                        "</span></td><td class='password'><div class='material-icons'>edit</div><span>" + results[i].user_password +
                        "</span></td><td class='role'>" + "<button type='button' class='role_switch_to_user'>Make User" +
                        "</button></td><td class='delete'>" + "<button type='button' class='deleteUser'>Delete" +
                        "</button></td></tr>"
                    );
                }
            }
            admin_list_jsdom.window.document.getElementById("user-container").innerHTML = admin_list;
            res.send(admin_list_jsdom.serialize());
        }
    );
});

//Authenticate user
app.post("/api/login", function (req, res) {
    res.setHeader("Content-Type", "application/json");

    let email = req.body.email;
    let pwd = req.body.password;

    connection.execute(
        "SELECT * FROM BBY_15_User WHERE email = ? AND user_password = ?",
        [email, pwd],
        function (error, results, fields) {
            if (results.length > 0) {
                // user authenticated, create a token
                const token = jwt.sign({
                    name : results[0].first_name,
                    isAdmin : results[0].admin_role,
                    userID : results[0].user_id},
                    key, 
                    {expiresIn: "30m"});
                res.json({ 
                    status: "success",
                    token: token });
            } else {
                res.send({
                    status: "fail",
                    msg: "User account not found."
                });
            }
        }
    );
});


//Authenticating user, checks if they can be added to the database, then creates and add the user info into the database.
app.post("/api/add-user", function (req, res) {
    let firstName = req.body.firstName;
    let lastName = req.body.lastName;
    let signupemail = req.body.email;
    let signuppassword = req.body.password;
    let regex = new RegExp("[^.]+([p{L|M|N|P|S} ]*)+[^\.]@[^\.]+([p{L|M|N|P|S} ]*).+[^\.]$");

    //Checking to see if any columns in the sign-up page is NULL : if they are, the account cannot be made.
    if (!firstName || !lastName || !signupemail || !signuppassword) {
        res.send({
            status: "fail",
            msg: "Every column has to be filled."
        });
    } else {
        if (!regex.test(signupemail)) {
            res.send({
                status: "invalid email",
                msg: "This email is invalid."
            });
        } else {
            connection.query('INSERT INTO BBY_15_User (first_name, last_name, email, user_password) VALUES (?, ?, ?, ?)',
                [req.body.firstName, req.body.lastName, req.body.email, req.body.password],
                function (error, results, fields) {
                    if (error && error.errno == 1062) {
                        res.send({
                            status: "duplicate",
                            msg: "This email is already registered to an account."
                        });
                    } else {
                        // user created, create a token
                        const token = jwt.sign({
                            name : firstName,
                            isAdmin : false,
                            userID : results.insertId},
                            key, 
                            {expiresIn: "30m"});
                        res.send({ 
                            status: "success",
                            msg: "Record added.",
                            token: token });
                    }
                }
            );
        }

    }
});

//Authenticating user, checks if they can be added to the database, then creates and add the user info into the database.
app.post("/api/add-user-as-admin", function (req, res) {
    res.setHeader('Content-Type', 'application/json');

    let firstName = req.body.firstName;
    let lastName = req.body.lastName;
    let signupemail = req.body.email;
    let signuppassword = req.body.password;
    let regex = new RegExp("[^.]+([p{L|M|N|P|S} ]*)+[^\.]@[^\.]+([p{L|M|N|P|S} ]*).+[^\.]$");

    //Checking to see if any columns in the sign-up page is NULL : if they are, the account cannot be made.
    if (!firstName || !lastName || !signupemail || !signuppassword) {
        res.send({
            status: "fail",
            msg: "Every column has to be filled."
        });
    } else {
        if (!regex.test(signupemail)) {
            res.send({
                status: "invalid email",
                msg: "This email is invalid."
            });
        } else {
            //connecting to the database, then creating and adding the user info into the database.
            connection.query('INSERT INTO BBY_15_User (first_name, last_name, email, user_password) VALUES (?, ?, ?, ?)',
                [req.body.firstName, req.body.lastName, req.body.email, req.body.password, ],
                function (error, results, fields) {
                    if (error && error.errno == 1062) {
                        res.send({
                            status: "duplicate",
                            msg: "This email is already registered to an account."
                        });
                    } else {
                        res.send({
                            status: "success",
                            msg: "Record added."
                        });
                    }
                });
        }
    }
});


//Get the user 's information from the database and display information on the profile page
app.get("/api/profile", function (req, res) {
    const userID = parseToken(req)?.userID;

    connection.query(
        "SELECT * FROM BBY_15_User WHERE user_id = ?",
        [userID],
        function (error, results, fields) {
            let profileDOM = new JSDOM(profile);
            if (results.length > 0) {
                for (var i = 0; i < results.length; i++) {
                    let firstname = results[i].first_name;
                    let lastname = results[i].last_name;
                    let useremail = results[i].email;
                    let password = results[i].user_password;
                    let userprofile = 'https://extremis-bby15.s3.ca-central-1.amazonaws.com/default-profile.jpg';
                    if (results[i].profile_picture != null) {
                        userprofile = results[i].profile_picture;
                    }
                    var template = `   
                    </br>  
                    <div class="account-body"> 
                    <div class='profile-pic-div'>
                        <img class='profile-pic' src='${userprofile}'>
                        <label for="selectFile">
                            <img class="camera" src="https://extremis-bby15.s3.ca-central-1.amazonaws.com/camera-icon1.jpg" width="28" height="28"/>
                        </label>
                        <input type="file" class="btn" id="selectFile" accept="image/png, image/gif, image/jpeg"
                        multiple="multiple" />

                    </div>                         
                        <div id="user_title">
                        <h2>${firstname} ${lastname} </h2>
                        </div>
                        <div id="user_content">
                            <div class="form-group">
                                <label for="firstName">First Name
                                    <div class="tooltip">&#x270e;
                                        <p class="tooltiptext">Click on text to edit</p>
                                    </div>  
                                </label>
                                <input type="text" class="um-input" id="firstName" value=${firstname}> 
                            </div>
                            <div class="form-group">
                                <label for="lastName">Last Name
                                    <div class="tooltip">&#x270e;
                                        <p class="tooltiptext">Click on text to edit</p>
                                    </div> 
                                </label>
                                <input type="text" class="um-input" id="lastName" value=${lastname}>
                            </div>
                            <div class="form-group">
                                <label for="email">Email</label>
                                <input type="email" class="um-input" id="userEmail" disabled value=${useremail}>
                            </div>
                            <div class="form-group">
                                <label for="password">Password
                                    <div class="tooltip">&#x270e;
                                        <p class="tooltiptext">Click on text to edit</p>
                                    </div> 
                                </label>
                                <input type="password" id="userPassword" required="required"value=${password} />
                                <i class="fa-solid fa-eye togglePassword"></i>
                            </div>
                            <div class="form-group">
                                <label for="password">Confirm password
                                    <div class="tooltip">&#x270e;
                                        <p class="tooltiptext">Click on text to edit</p>
                                    </div> 
                                </label>
                                <input type="password" id="userConfirmPassword" required="required"
                                value=${password} onkeyup="validate_password()"/>
                                <i class="fa-solid fa-eye togglePassword"></i>
                            </div>
                        </div>
                            
                        </div>  
                    </div>
                `;
                    let area = profileDOM.window.document.querySelector('#user_content');
                    area.innerHTML += template;
                }
            }
        }
    )
});

//Store user update information and avatar
app.post("/api/profile", function (req, res) {
    const userID = parseToken(req)?.userID;
    const adminStatus = parseToken(req)?.isAdmin;

    let regex = new RegExp("[^.]+([p{L|M|N|P|S} ]*)+[^\.]@[^\.]+([p{L|M|N|P|S} ]*).+[^\.]$");

    if (!regex.test(req.body.email)) {
        res.send({
            status: "invalid email",
            msg: "This email is invalid."
        });
    } else {
        //connecting to the database, then creating and adding the user info into the database.
        connection.query('UPDATE BBY_15_User SET first_name=?, last_name=?, email=?, user_password=? WHERE user_id=?',
            [req.body.firstName, req.body.lastName, req.body.email, req.body.password, userID],
            function (error, results, fields) {
                const token = jwt.sign({
                    name : req.body.firstName,
                    isAdmin : adminStatus,
                    userID : userID},
                    key, 
                    {expiresIn: "30m"});
                res.send({ 
                    status: "success",
                    msg: "Record added.",
                    token: token });
            });
    }
});

// Set up the storage and file name for uploaded images
// Store images in avatar folder in system if user is accessing through local host
var storage_avatar = multer.diskStorage({
    destination: function (req, file, callback) {
        callback(null, "");
    },
    filename: function (req, file, callback) {
        //callback(null, req.session.user_id + "AT" + Date.now() + "AND" + file.originalname);
        callback(null, "AT" + Date.now() + "AND" + file.originalname);
    }
});
const uploadAvatar = multer({
    storage: storage_avatar
});

//Upload the user profle into the database
app.post('/api/upload-avatar', uploadAvatar.array("files"), async function (req, res) {
    const userID = parseToken(req)?.userID;

    for (let i = 0; i < req.files.length; i++) {
        var newPath;
        req.files[i].filename = req.files[i].originalname;

        // Upload image onto S3 bucket
        let folderName = "avatar/";
        const result = await s3.uploadFile(req.files[i], folderName);
        newPath = result.Location;

        connection.query('UPDATE BBY_15_User SET profile_picture=? WHERE user_id=?',
            [newPath, userID],
            function (error, results, fields) {
                res.send({
                    status: "success",
                    msg: "Image information added to database."
                });
            });
    }
});

/** ANOTHER POST: we are changing stuff on the server!!!
 *  This function updates the user on the user-list and the admin-list
 */
app.post('/api/update-user', function (req, res) {
    res.setHeader('Content-Type', 'application/json');

    let regex = new RegExp("[^.]+([p{L|M|N|P|S} ]*)+[^\.]@[^\.]+([p{L|M|N|P|S} ]*).+[^\.]$");
    if (!regex.test(req.body.email)) {
        res.send({
            status: "invalid email",
            msg: "This email is invalid."
        });
    } else {
        connection.query('UPDATE BBY_15_User SET first_name = ?, last_name = ?, email = ?, user_password = ? WHERE user_id = ?',
            [req.body.firstName, req.body.lastName, req.body.email, req.body.password, parseInt(req.body.id)],
            function (error, results, fields) {
                if (error && error.errno == 1062) {
                    res.send({
                        status: "duplicate",
                        msg: "This email is already registered to an account."
                    });
                } else {
                    res.send({
                        status: "success",
                        msg: "Recorded updated."
                    });
                }
            });
    }
});
/** POST: we are changing stuff on the server!!!
 *  This user allows admins to click on delete user button to delete the user in the following row.
 */
app.post('/api/delete-user', function (req, res) {
    res.setHeader('Content-Type', 'application/json');
    connection.query('DELETE FROM BBY_15_User WHERE user_id = ?',
        [parseInt(req.body.id)],
        function (error, results, fields) {
            if (error) {
                console.log(error);
            }
            res.send({
                status: "success",
                msg: "Recorded deleted."
            });
        });
});

/**
 * This functions allows admins to change other admin into regular users.
 */
app.post('/api/make-user', function (req, res) {
    res.setHeader('Content-Type', 'application/json');
    connection.query('UPDATE BBY_15_User SET admin_role = 0 WHERE user_id = ?',
        [parseInt(req.body.id)],
        function (error, results, fields) {
            if (error) {
                console.log(error);
            }
            res.send({
                status: "success",
                msg: "Recorded deleted."
            });

        });
});

/**
 * This function allows admins to change other regular users into admin users.
 */
app.post('/api/make-admin', function (req, res) {
    res.setHeader('Content-Type', 'application/json');
    connection.query('UPDATE BBY_15_User SET admin_role = 1 WHERE user_id = ?',
        [parseInt(req.body.id)],
        function (error, results, fields) {
            if (error) {
                console.log(error);
            }
            res.send({
                status: "success",
                msg: "Recorded deleted."
            });
        });
});

const sanitizeHtml = require("sanitize-html");

/**
 * Store text data of user's post into the database.
 * The following codes follow Instructor Arron's example with changes and adjustments made by Linh.
 */
app.post("/api/add-post", function (req, res) {
    res.setHeader('Content-Type', 'application/json');

    // Sanitize html code on the server (https://www.npmjs.com/package//sanitize-html)
    const stringToSanitize = req.body.postContent;
    const clean = sanitizeHtml(stringToSanitize, {
        allowedTags: [
            "address", "article", "aside", "footer", "header", "h1", "h2", "h3", "h4",
            "h5", "h6", "hgroup", "main", "nav", "section", "blockquote", "dd", "div",
            "dl", "dt", "figcaption", "figure", "hr", "li", "main", "ol", "p", "pre",
            "ul", "a", "abbr", "b", "bdi", "bdo", "br", "cite", "code", "data", "dfn",
            "em", "i", "kbd", "mark", "q", "rb", "rp", "rt", "rtc", "ruby", "s", "samp",
            "small", "span", "strong", "sub", "sup", "time", "u", "var", "wbr", "caption",
            "col", "colgroup", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "span"
        ],
        disallowedTagsMode: ['discard'],
        allowedAttributes: {
            a: ['href', 'name', 'target'],
            img: ['srcset', 'alt', 'title', 'width', 'height', 'loading'],
            span: ['style']
        },
        selfClosing: ['br', 'hr', 'area', 'base', 'basefont', 'input', 'link', 'meta'],

        allowedIframeHostnames: ['www.youtube.com']
    });

    const payload = parseToken(req);
    let post_type = req.body.postType;
    let post_title = req.body.postTitle;
    let post_location = req.body.postLocation;
    let post_content = clean;
    let weather_type = req.body.weatherType;
    let userID = payload?.userID;
    let post_time = new Date(Date.now());
    let post_status = "pending";

    connection.query('INSERT INTO BBY_15_Post (user_id, posted_time, post_content, post_title, post_type, location, post_status, weather_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [userID, post_time, post_content, post_title, post_type, post_location, post_status, weather_type],
        function (error, results, fields) {
            payload.postID = results.insertId;
            const newToken = jwt.sign(payload, key, {expiresIn: "30m"});
            res.send({
                status: "success",
                msg: "Post added to database.",
                token: newToken
            });
        });
});

/**
 * Store images information into the database. These images are uploaded by users when they create a post.
 * The following codes follow Instructor Arron's example with changes and adjustments made by Linh.
 */
var s3 = require('./s3');

// Store images in post-images folder in system if user is accessing through local host
var storage_post_images = multer.diskStorage({
    destination: function (req, file, callback) {
        callback(null, "")
    },
    filename: function (req, file, callback) {
        //callback(null, req.session.user_id + "AT" + Date.now() + "AND" + file.originalname);
        callback(null, "AT" + Date.now() + "AND" + file.originalname);
    }
});
var uploadPostImages = multer({
    storage: storage_post_images
});

app.post('/api/upload-post-images', uploadPostImages.array("files"), async function (req, res) {
    const postID = parseToken(req)?.postID;

    if (req.files.length > 0) {
        for (let i = 0; i < req.files.length; i++) {
            req.files[i].filename = req.files[i].originalname;
            
            // Upload image onto S3 bucket
            let folderName = "post-images/"
            const result = await s3.uploadFile(req.files[i], folderName);
            var newpathImages = result.Location;

            connection.query('INSERT INTO BBY_15_Post_Images (post_id, image_location) VALUES (?, ?)',
                [postID, newpathImages],
                function (error, results, fields) {});
        }
        res.send({
            status: "success",
            msg: "Image information added to database."
        });
    } else {
        connection.query('INSERT INTO BBY_15_Post_Images (post_id, image_location) VALUES (?, ?)',
            [postID, "https://extremis-bby15.s3.ca-central-1.amazonaws.com/default-profile.jpg"],
            function (error, results, fields) {});
        res.send({
            status: "success",
            msg: "No image has been uploaded"
        });
    }
});

//Get the post and event information from the database and display information on the timeline page
app.get("/api/timeline", function (req, res) {
    connection.query(`SELECT * FROM BBY_15_User 
        INNER JOIN BBY_15_post ON BBY_15_User.user_id = BBY_15_Post.user_id 
        LEFT JOIN BBY_15_post_images ON BBY_15_post.post_id = BBY_15_post_images.post_id 
        WHERE post_status = "approved" OR post_status = "pending"
        ORDER BY posted_time DESC`,
        function (error, results, fields) {
            let timeline = fs.readFileSync("../app/html/timeline.html", "utf8");
            let timelineDOM = new JSDOM(timeline);
            if (results.length >= 0) {
                for (var i = 0; i < results.length; i++) {
                    let firstName = results[i].first_name;
                    let lastName = results[i].last_name;
                    let postTime = results[i].posted_time;
                    let contentPost = results[i].post_content;
                    let postTitle = results[i].post_title;
                    let postlocation = results[i].location;
                    let typeWeather = results[i].weather_type;
                    let postImages = results[i].image_location;
                    let profilePic;
                    if (results[i].profile_picture != null) {
                        profilePic = results[i].profile_picture;
                    } else {
                        profilePic = "https://extremis-bby15.s3.ca-central-1.amazonaws.com/default-profile.jpg";
                    }
                    var template = `   
                    </br>  
                    <div class="post_content">
                        <div class="card">
                            <div class="post-user">
                                <img class="profile-pic" src="${profilePic}" onclick='expandImage(this)'>
                                <span><h4>&ensp;${firstName} ${lastName}</h4></span>
                            </div>
            
                            <div class="post-header">
                                <h3><b>${postTitle}</b></h3> 
                                <h4>Type: ${typeWeather}</h4> 
                                <h5>Location: ${postlocation}</h5> 
                            </div>
                            <div class="post-image">`;
                    if (postImages != "https://extremis-bby15.s3.ca-central-1.amazonaws.com/default-profile.jpg") {
                        template += `<img class='post-pic' src="${postImages}" onclick="expandImage(this)">`;
                    }

                    while (results[i].post_id && results[i + 1] && (results[i].post_id == results[i + 1].post_id)) {
                        i++;
                        if (results[i].image_location != "https://extremis-bby15.s3.ca-central-1.amazonaws.com/default-profile.jpg") {
                            template += "<img class='post-pic' src=" + results[i].image_location + " onclick='expandImage(this)'>"
                        }
                    }

                    template += `</div>
                            <div class="desc">
                                <p class="time">Posted time: ${postTime}</p> 
                                <p>Description: ${contentPost}</p>
                            </div>
                            <p class="read-more"><a href="#" class="read-more-button">Read More</a></p>
                        </div>
                    </div>`;
                    let area = timelineDOM.window.document.querySelector('.post_content');
                    area.innerHTML += template;
                }
                res.send(timelineDOM.serialize());
            }
        }
    )
});

app.post('/api/search-timeline', function (req, res) {
    const term = req.body.searchTerm;

    connection.query(`SELECT * FROM BBY_15_User
    INNER JOIN BBY_15_post ON BBY_15_User.user_id = BBY_15_Post.user_id 
    LEFT JOIN BBY_15_post_images 
    ON BBY_15_post.post_id = BBY_15_post_images.post_id 
    WHERE (LOWER(post_content) LIKE '%${term}%'
    OR LOWER(post_title) LIKE '%${term}%'
    OR LOWER(post_type) LIKE '%${term}%'
    OR LOWER(location) LIKE '%${term}%'
    OR LOWER(weather_type) LIKE '%${term}%')
    AND (post_status = "approved" OR post_status = "pending")
    ORDER BY posted_time DESC`,
        function (error, results, fields) {
            if (results.length >= 0) {
                var template = "";
                for (var i = 0; i < results.length; i++) {
                    let firstName = results[i].first_name;
                    let lastName = results[i].last_name;
                    let postTime = results[i].posted_time;
                    let contentPost = results[i].post_content;
                    let postTitle = results[i].post_title;
                    let postlocation = results[i].location;
                    let typeWeather = results[i].weather_type;
                    let postImages = results[i].image_location;
                    let profilePic;
                    if (results[i].profile_picture != null) {
                        profilePic = results[i].profile_picture;
                    } else {
                        profilePic = "https://extremis-bby15.s3.ca-central-1.amazonaws.com/default-profile.jpg";
                    }
                    template += `   
                </br>  
                <div class="post_content">
                    <div class="card">
                        <div class="post-user">
                            <img class="profile-pic" src="${profilePic}">
                            <span><h4>&ensp;${firstName} ${lastName}</h4></span>
                        </div>
        
                        <div class="post-header">
                            <h3><b>${postTitle}</b></h3> 
                            <h4>Type: ${typeWeather}</h4> 
                            <h5>Location: ${postlocation}</h5> 
                        </div>
                        <div class="post-image">`;
                    if (postImages != "https://extremis-bby15.s3.ca-central-1.amazonaws.com/default-profile.jpg") {
                        template += `<img class='post-pic' src="${postImages}"  onclick="expandImage(this)">`;
                    }
                    while (results[i].post_id && results[i + 1] && (results[i].post_id == results[i + 1].post_id)) {
                        i++;
                        if (results[i].image_location != "https://extremis-bby15.s3.ca-central-1.amazonaws.com/default-profile.jpg") {
                            template += "<img class='post-pic' src=" + results[i].image_location + " onclick='expandImage(this)'>"
                        }
                    }

                    template += `</div>
                        <div class="desc">
                            <p class="time">Posted time: ${postTime}</p> 
                            <p>Description: ${contentPost}</p>
                        </div>
                        <p class="read-more"><a href="#" class="read-more-button">Read More</a></p>
                    </div>
                </div>`;
                }
                //res.send(timelineDOM.serialize());
                res.send({
                    status: "success",
                    message: template
                });
            }
        }
    )
});

/**
 * Display all posts on the Manage-Post page using the card template in post-list.html.
 * The following codes follow Instructor Arron's example with changes and adjustments made by Linh.
 */
app.get("/api/post-list", function (req, res) {
    connection.query(
        "SELECT * FROM BBY_15_post LEFT JOIN BBY_15_post_images ON BBY_15_post.post_id = BBY_15_post_images.post_id ORDER BY posted_time DESC",
        [],
        function (error, results, fields) {
            let postList = fs.readFileSync("../app/html/post-list.html", "utf8");
            let postListDOM = new JSDOM(postList);
            let cardTemplate = postListDOM.window.document.getElementById("postCardTemplate");
            if (results.length >= 0) {
                for (var i = 0; i < results.length; i++) {
                    let newcard = cardTemplate.content.cloneNode(true);
                    newcard.querySelector('.current-status').innerHTML = results[i].post_status + ' <i class="fa-solid fa-pen"></i>';
                    newcard.querySelector('.userID').innerHTML = "<b>User ID: </b>" + results[i].user_id;
                    newcard.querySelector('.post-type').innerHTML = "<b>Type: </b>" + results[i].post_type;
                    newcard.querySelector('.post-title').innerHTML = "<b>Title: </b>" + results[i].post_title;
                    newcard.querySelector('.weather-type').innerHTML = "<b>Weather Type: </b>" + results[i].weather_type;
                    newcard.querySelector('.post-location').innerHTML = "<b>Location: </b>" + results[i].location;
                    newcard.querySelector('.post-time').innerHTML = "<b>Time: </b>" + results[i].posted_time;
                    newcard.querySelector('.post-content').innerHTML = "<b>Content: </b>" + results[i].post_content;
                    newcard.querySelector('.postID').innerHTML = results[i].post_id;

                    if (results[i].image_location == "https://extremis-bby15.s3.ca-central-1.amazonaws.com/default-profile.jpg") {
                        // Set src property of img tag as default and display property as none if the post has no images
                        newcard.querySelector('.card-images').innerHTML = '<img class="card-image" src="' + results[i].image_location + '" alt="no image" style="display: none" />';
                    } else {
                        let str = '<img class="card-image" src="' + results[i].image_location + '" onclick = "expandImage(this)" alt="post image"/>';
                        // Set src property of img tag as the image path
                        while (results[i].post_id && results[i + 1] && (results[i].post_id == results[i + 1].post_id)) {
                            i++;
                            if (results[i].image_location != "https://extremis-bby15.s3.ca-central-1.amazonaws.com/default-profile.jpg") {
                                str += '<img class="card-image" src="' + results[i].image_location + '" onclick = "expandImage(this)" alt="post image"/>';
                            }
                        }
                        newcard.querySelector('.card-images').innerHTML = str;
                    }

                    //Add Read more button if the total length of the post content is more than 500
                    if (results[i].post_content.length >= 500) {
                        let p = postListDOM.window.document.createElement("p");
                        p.setAttribute("class", "read-more");
                        newcard.querySelector('.sidebar-box').appendChild(p);
                        newcard.querySelector('.read-more').innerHTML = '<button onclick="expandText(this)" class="more-button">Read More</button>';

                    }
                    postListDOM.window.document.getElementById("post-goes-here").appendChild(newcard);
                }
            }
            res.send(postListDOM.serialize());
        })
});

// Update the status section of a post.
app.post("/api/update-status", function (req, res) {
    res.setHeader('Content-Type', 'application/json');

    let postID = req.body.postID;
    let status = req.body.postStatus;

    connection.query(
        "UPDATE BBY_15_post SET post_status = ? WHERE post_id = ?",
        [status, postID],
        function (error, results, fields) {
            res.send({
                status: "success",
                msg: "Post status has been updated in database."
            });
        })
});

/**
 * Redirect to the my post and show all the posts that created by a user.
 * The following codes follow Instructor Arron's example with changes and adjustments made by Anh Nguyen
 */
app.get("/api/my-post", function (req, res) {
    const userID = parseToken(req)?.userID;

    connection.query(
        `SELECT posted_time, post_content, BBY_15_post.post_id, post_title, location, weather_type, image_location, post_status 
        FROM BBY_15_post LEFT JOIN BBY_15_post_images ON BBY_15_post.post_id = BBY_15_post_images.post_id WHERE user_id = ?
        ORDER BY posted_time DESC`,
        [userID],
        function (error, results, fields) {
            let my_post_jsdom = new JSDOM(doc);
            res.setHeader("Content-Type", "text/html");
            if (results != null) {
                for (let i = 0; i < results.length; i++) {
                    let postTime = results[i].posted_time;
                    let contentPost = results[i].post_content;
                    let postID = results[i].post_id;
                    let postTitle = results[i].post_title;
                    let postlocation = results[i].location;
                    let typeWeather = results[i].weather_type;
                    let postImages = results[i].image_location;
                    let postStatus = results[i].post_status;
                    var my_post = `   
                    </br>  
                    <div class="my-post-content">
                        <div class="card">
                            <div class="post-image">
                                
                                <div class="image">`;
                    if (postImages != "https://extremis-bby15.s3.ca-central-1.amazonaws.com/default-profile.jpg") {
                        my_post += `<div class="po-image">
                        <img class="remove-icon"src="/assets/remove.png" width="18" height="18">
                        <img class='image' src="${postImages}">
                        </div>`;
                    }

                    while (results[i].post_id && results[i + 1] && (results[i].post_id == results[i + 1].post_id)) {
                        i++;
                        if (results[i].image_location != "https://extremis-bby15.s3.ca-central-1.amazonaws.com/default-profile.jpg") {
                            my_post += `<div class="po-image">
                            <img class="remove-icon"src="/assets/remove.png" width="18" height="18">
                            `
                            my_post += "<img class='image' src=" + results[i].image_location + "></div>"
                        }
                    }
                    my_post += `</div>
                                    <div class="desc">
                                        <p class="post_id">` + postID + `</p> 
                                        <p class="posted_time"><u>Posted time:</u>  ` + postTime + `</p><br> 
                                        <p class="post_status"><u>Post status:</u> ` + postStatus + `</p> </br>                                            
                                        <u>Weather Type:</u>  
                                        <div class="tooltip">&#x270e;
                                            <p class="tooltiptext">Click on text to edit</p>
                                        </div>    
                                        <h3 class="weather_type"><span>` + typeWeather + `</span></h3><br>
                                        <u>Title:</u>
                                        <div class="tooltip">&#x270e;
                                            <p class="tooltiptext">Click on text to edit</p>
                                        </div>      
                                        <h4 class="post_title"><span>` + postTitle + `</span></h4><br> 
                                        <u>Location:</u> 
                                        <div class="tooltip">&#x270e;
                                            <p class="tooltiptext">Click on text to edit</p>
                                        </div>             
                                        <p class="location"><span>` + postlocation + `</span></p><br> 
                                        <u>Description:</u> 
                                        <div class="tooltip">&#x270e;
                                            <p class="tooltiptext">Click on text to edit</p>
                                        </div>        
                                        </br><div class="post_content" onclick="editContent(this)">` + contentPost + `</div>
                                        <form class="upload-images">
                                            <label>Add image: </label>
                                            <input type="file" class="btn selectFile" class="selectFile" accept="image/png, image/gif, image/jpeg"/>
                                            <p class="errorMsg"></p>
                                            <div class="button-update-images">
                                                <button class="delete1">Delete</button> 
                                                
                                            <input class="form-input" type="submit" id="upload" value="Upload image" />                                                    
                                            </div>
                                        </form>
                                    </div>
                                    <div class="form-box-image">
                                </div>
                            </div>
                        `;
                    my_post_jsdom.window.document.getElementById("my-post-content").innerHTML += my_post;
                }
            }
            res.send(my_post_jsdom.serialize());
        }
    )
});

/**
 * Delete post from users.
 * The following codes follow Instructor Arron's example with changes and adjustments made by Anh Nguyen
 */
app.post('/api/delete-post', function (req, res) {
    res.setHeader('Content-Type', 'application/json');
    connection.query('DELETE FROM BBY_15_post WHERE post_id = ?',
        [req.body.post_id],
        function (error, results, fields) {
            if (error) {
                console.log(error);
            }
            res.send({
                status: "success",
                msg: "Recorded deleted."
            });
        });
});

/**
 * Updates new posts that changed based on the user's input
 * The following codes follow Instructor Arron's example with changes and adjustments made by Anh Nguyen.
 */
app.post("/api/update-post", function (req, res) {
    const userID = parseToken(req)?.userID;
    res.setHeader('Content-Type', 'application/json');
    connection.query('UPDATE BBY_15_post SET post_title = ?, location = ?, weather_type = ? WHERE post_id = ? AND user_id = ?',
        [req.body.post_title, req.body.location, req.body.weather_type, req.body.post_id, userID],
        function (error, results, fields) {
            if (error) {
                console.log(error);
            }
            res.send({
                status: "success",
                msg: "Recorded updated."
            });
        });
});

// Updates the content of post
app.post("/api/update-post-content", function (req, res) {
    const userID = parseToken(req)?.userID;
    res.setHeader('Content-Type', 'application/json');
    connection.query('UPDATE BBY_15_post SET post_content = ? WHERE post_id = ? AND user_id = ?',
        [req.body.post_content, req.body.post_id, userID],
        function (error, results, fields) {
            if (error) {
                console.log(error);
            }
            res.send({
                status: "success",
                msg: "Recorded updated."
            });
        });
});

// When adding images, this function saves the ID of the post ahead of the image itself
app.post("/api/change-images-post-data", function (req, res) {
    const payload = parseToken(req);
    payload.postID = req.body.p;
    const newToken = jwt.sign(payload, key, {expiresIn: "30m"});
    res.send({
        status: "success",
        token: newToken
    });
})

/**
 * Redirect to the my post and update the new images if user changes post's images
 * The following codes follow Instructor Arron's example with changes and adjustments made by Anh Nguyen.
 */
app.post("/api/change-images-post", uploadPostImages.array("files"), async function (req, res) {
    const postID = parseToken(req)?.postID;

    for (let i = 0; i < req.files.length; i++) {
        req.files[i].filename = req.files[i].originalname;

        // Upload image onto S3 bucket
        let folderName = "post-images/"
        const result = await s3.uploadFile(req.files[i], folderName);
        var newpath = result.Location;

        connection.query('INSERT INTO BBY_15_Post_Images (post_id, image_location) VALUES (?, ?)',
            [postID, newpath],
            function (error, results, fields) {
                res.send({
                    status: "success",
                    msg: "Image information added to database."
                });
            });
    }
});

/**
 * Delete an image on the post
 * The following codes follow Instructor Arron's example with changes and adjustments made by Anh Nguyen.
 */
app.post('/api/delete-image', function (req, res) {
    res.setHeader('Content-Type', 'application/json');
    connection.query('DELETE FROM BBY_15_post_images WHERE image_location=?',
        [req.body.image],
        function (error, results, fields) {
            if (error) {
                console.log(error);
            }
            res.send({
                status: "success",
                msg: "Recorded deleted."
            });
        });
});