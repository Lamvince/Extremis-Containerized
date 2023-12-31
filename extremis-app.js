/**
 * These following codes is adapted from instructor Arron's 2537 examples and changes made by our team.
 * @author Arron_Ferguson (1537 instructor) and students from team BBY15: Anh Nguyen, Linh Nguyen, Vincent Lam and Dongwan_Kang.
 * @param {*} data user input
 */

"use strict";

const express = require('express');
const session = require("express-session");
const mysql = require("mysql2");
const app = express();
const fs = require("fs");
const {
    JSDOM
} = require('jsdom');
const multer = require("multer");

app.use("/assets", express.static("./public/assets"));
app.use("/css", express.static("./public/css"));
app.use("/js", express.static("./public/js"));
app.use("/images", express.static("./app/images"));

app.use(session({
    secret: "what is the point of this secret",
    name: "extremisSessionID",
    resave: false,
    saveUninitialized: true
}));

app.use(express.json());
app.use(express.urlencoded({
    extended: true
}));


/**
 * Identify the connection. If users are accessing the website (Heroku), connect to Heroku host and database.
 * If users are accessing through local host, connect to local host and database in the system.
 * This code is from example of COMP2800 Instructor Patrick Guichon and changes made by our team.
 */
const isHeroku = process.env.IS_HEROKU || false;
//Since we have another git repository set up by Heroku, the information of the connection will not be shown here
const connectionHeroku = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
};

const connectionLocal = {
    host: "localhost",
    user: "root",
    password: "",
    database: "COMP2800"
};

if (isHeroku) {
    var connection = mysql.createPool(connectionHeroku);
    let port = process.env.PORT || 8000;
    app.listen(port, function () {});
    const {
        uploadFile
    } = require('./s3');
} else {
    var connection = mysql.createPool(connectionLocal);
    let port = 8000
    app.listen(port, function () {});
}



/**
 * Redirect users to main page if they have logged in and are not admin.
 * Redirect users to admin dashboard page if they have logged in and are admin.
 * Otherwise, redirect users to login page.
 */
app.get('/', function (req, res) {
    if (req.session.loggedIn && !req.session.isAdmin) {
        // if user has logged in and is not an admin, redirect to main page
        res.redirect("/main");
    } else if (req.session.loggedIn && req.session.isAdmin) {
        // if user has logged in and is an admin, redirect to main page
        res.redirect("/dashboard");
    } else {
        let doc = fs.readFileSync("./app/html/login.html", "utf8");

        res.set("Server", "Extremis");
        res.set("X-Powered-By", "BBY15");
        res.send(doc);
    }

});


//Redirect users to the main page if they have logged in. Otherwise, redirect to login page.
app.get("/main", function (req, res) {
    if (req.session.loggedIn && !req.session.isAdmin) {
        let doc = fs.readFileSync("./app/html/main.html", "utf8");
        res.setHeader("Content-Type", "text/html");
        let main_jsdom = new JSDOM(doc);
        main_jsdom.window.document.getElementById("header-name").innerHTML = "<h5 class='um-subtitle'> Hello " + req.session.firstName + ". Welcome to</h5>";
        res.write(main_jsdom.serialize());
        res.end();

    } else {
        res.redirect("/");
    }

});

//Redirect admin users to the admin dashboard page if they have logged in. Otherwise, redirect to login page.
app.get("/dashboard", function (req, res) {
    if (req.session.loggedIn && req.session.isAdmin) {
        let doc = fs.readFileSync("./app/html/dashboard.html", "utf8");
        res.setHeader("Content-Type", "text/html");
        let dashboard_jsdom = new JSDOM(doc);
        dashboard_jsdom.window.document.getElementById("header-name").innerHTML = "<h5 class='um-subtitle'> Welcome " + req.session.firstName + "</h5>";
        res.write(dashboard_jsdom.serialize());
        res.end();
    } else {
        res.redirect("/");
    }
});

app.get("/add-user", function (req, res) {
    if (req.session.loggedIn && req.session.isAdmin) {
        let doc = fs.readFileSync("./app/html/add-user.html", "utf8");
        res.setHeader("Content-Type", "text/html");
        let dashboard_jsdom = new JSDOM(doc);
        res.write(dashboard_jsdom.serialize());
        res.end();
    } else {
        res.redirect("/");
    }

});

app.get("/weather-forecast", function (req, res) {
    if (req.session.loggedIn && !req.session.isAdmin) {
        let doc = fs.readFileSync("./app/html/weather-forecast.html", "utf8");
        res.setHeader("Content-Type", "text/html");
        let dashboard_jsdom = new JSDOM(doc);
        res.write(dashboard_jsdom.serialize());
        res.end();
    } else {
        res.redirect("/");
    }

});

//function needed for getting list of all users in user-list
app.get("/user-list", function (req, res) {
    if (req.session.loggedIn) {
        let doc = fs.readFileSync("./app/html/user-list.html", "utf8");
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
    } else {
        // if user has not logged in, redirect to login page
        res.redirect("/");
    }
});

app.get("/edit", function (req, res) {
    if (req.session.loggedIn && req.session.isAdmin) {
        let doc = fs.readFileSync("./app/html/edit.html", "utf8");
        res.setHeader("Content-Type", "text/html");
        let dashboard_jsdom = new JSDOM(doc);
        res.write(dashboard_jsdom.serialize());
        res.end();
    } else {
        res.redirect("/");
    }
});

// function for getting all admins for admin-list
app.get("/admin-list", function (req, res) {
    if (req.session.loggedIn) {
        let doc = fs.readFileSync("./app/html/admin-list.html", "utf8");
        let admin_list_jsdom = new JSDOM(doc);
        res.setHeader("Content-Type", "text/html");

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
                    if (req.session.user_id != results[i]['user_id']) {
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
    } else {
        // if user has not logged in, redirect to login page
        res.redirect("/");
    }
});

//function needed for redirecting to manage admins list in dashboard
app.get("/admin-list", function (req, res) {
    if (req.session.loggedIn) {
        let doc = fs.readFileSync("./app/html/admin-list.html", "utf8");
        res.setHeader("Content-Type", "text/html");
        res.send(doc);
    } else {
        // if user has not logged in, redirect to login page
        res.redirect("/");
    }

});

//function needed for redirecting to manage admins list in dashboard
app.get("/about-us", function (req, res) {
    if (req.session.loggedIn) {
        let doc = fs.readFileSync("./app/html/about-us.html", "utf8");
        res.setHeader("Content-Type", "text/html");
        let aboutUsDOM = new JSDOM(doc);
        // Display My Post on navbar if the user is not an admin
        if (!req.session.isAdmin) {
            res.send(doc);
        } else {
            aboutUsDOM.window.document.getElementById("myPostLink").remove();
            res.send(aboutUsDOM.serialize());
        }

    } else {
        // if user has not logged in, redirect to login page
        res.redirect("/");
    }

});

//function needed for redirecting into the sign-up page.
app.get("/sign-up", function (req, res) {
    let doc = fs.readFileSync("./app/html/sign-up.html", "utf8");
    res.setHeader("Content-Type", "text/html");
    res.send(doc);
});

//Authenticate user
app.post("/login", function (req, res) {
    res.setHeader("Content-Type", "application/json");

    let email = req.body.email;
    let pwd = req.body.password;

    connection.execute(
        "SELECT * FROM BBY_15_User WHERE email = ? AND user_password = ?",
        [email, pwd],
        function (error, results, fields) {

            if (results.length > 0) {
                // user authenticated, create a session
                req.session.loggedIn = true;
                req.session.firstName = results[0].first_name;
                req.session.email = email;
                req.session.isAdmin = results[0].admin_role;
                req.session.user_id = results[0].user_id;
                if (results[0].admin_role) {
                    res.send({
                        status: "success",
                        msg: "Logged in.",
                        isAdmin: true
                    });
                } else {
                    res.send({
                        status: "success",
                        msg: "Logged in.",
                        isAdmin: false
                    });
                }
                req.session.save(function (err) {
                    //session saved
                });

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
app.post("/add-user", function (req, res) {
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
                        res.send({
                            status: "success",
                            msg: "Record added."
                        });
                        req.session.loggedIn = true;
                        req.session.user_id = results.insertId;
                        req.session.firstName = req.body.firstName;
                        req.session.save(function (err) {});
                    }
                }
            );
        }

    }
});

//Authenticating user, checks if they can be added to the database, then creates and add the user info into the database.
app.post("/add-user-as-admin", function (req, res) {
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
app.get("/profile", function (req, res) {
    // check for a session first!
    if (req.session.loggedIn) {
        connection.query(
            "SELECT * FROM BBY_15_User WHERE user_id = ?",
            [req.session.user_id],
            function (error, results, fields) {
                let profile = fs.readFileSync("./app/html/profile.html", "utf8");
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
                    // Display My Post on navbar if the user is not an admin
                    if (!req.session.isAdmin) {
                        res.send(profileDOM.serialize());
                    } else {
                        profileDOM.window.document.getElementById("myPostLink").remove();
                        res.send(profileDOM.serialize());
                    }

                }
            }
        )
    } else {
        res.redirect("/");
    }
});

//Store user update information and avatar
app.post("/profile", function (req, res) {
    res.setHeader('Content-Type', 'application/json');

    let regex = new RegExp("[^.]+([p{L|M|N|P|S} ]*)+[^\.]@[^\.]+([p{L|M|N|P|S} ]*).+[^\.]$");

    if (!regex.test(req.body.email)) {
        res.send({
            status: "invalid email",
            msg: "This email is invalid."
        });
    } else {
        //connecting to the database, then creating and adding the user info into the database.
        connection.query('UPDATE BBY_15_User SET first_name=?, last_name=?, email=?, user_password=? WHERE user_id=?',
            [req.body.firstName, req.body.lastName, req.body.email, req.body.password, req.session.user_id],
            function (error, results, fields) {
                res.send({
                    status: "success",
                    msg: "Record added."
                });
                req.session.loggedIn = true;
                req.session.firstName = req.body.firstName;
                req.session.email = req.body.email;
                req.session.save(function (err) {});
            });
    }
});

// Set up the storage and file name for uploaded images
if (!isHeroku) {
    // Store images in avatar folder in system if user is accessing through local host
    var storage_avatar = multer.diskStorage({
        destination: function (req, file, callback) {
            callback(null, "./app/images/avatar/");
        },
        filename: function (req, file, callback) {
            callback(null, req.session.user_id + "AT" + Date.now() + "AND" + file.originalname.split('/').pop().trim());
        }
    });
} else {
    var storage_avatar = multer.diskStorage({
        destination: function (req, file, callback) {
            callback(null, "");
        },
        filename: function (req, file, callback) {
            callback(null, req.session.user_id + "AT" + Date.now() + "AND" + file.originalname);
        }
    });
}
const uploadAvatar = multer({
    storage: storage_avatar
});

//Upload the user profle into the database
app.post('/upload-avatar', uploadAvatar.array("files"), async function (req, res) {
    for (let i = 0; i < req.files.length; i++) {
        var newPath;
        req.files[i].filename = req.files[i].originalname;
        if (!isHeroku) {
            newPath = req.files[i].path.substring(3);
        } else {
            // Upload image onto S3 bucket
            let folderName = "avatar/";
            const result = await s3.uploadFile(req.files[i], folderName);
            newPath = result.Location;
        }

        connection.query('UPDATE BBY_15_User SET profile_picture=? WHERE user_id=?',
            [newPath, req.session.user_id],
            function (error, results, fields) {
                res.send({
                    status: "success",
                    msg: "Image information added to database."
                });
                req.session.save(function (err) {});
            });
    }
});


/** Logout from the website */
app.get("/logout", function (req, res) {
    if (req.session) {
        req.session.destroy(function (error) {
            if (error) {
                res.status(400).send("Unable to log out");
            } else {
                res.redirect("/");
            }
        });
    }
});

/** ANOTHER POST: we are changing stuff on the server!!!
 *  This function updates the user on the user-list and the admin-list
 */
app.post('/update-user', function (req, res) {
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
app.post('/delete-user', function (req, res) {
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
app.post('/make-user', function (req, res) {
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
app.post('/make-admin', function (req, res) {
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


/**
 * Redirect to the create-a-post page if user is a regular user and has logged in.
 * Otherwise, not allow accessing this site.
 * The following codes follow Instructor Arron's example with changes and adjustments made by Linh.
 */
app.get("/create-post", function (req, res) {
    if (req.session.loggedIn && !req.session.isAdmin) {
        let doc = fs.readFileSync("./app/html/create-post.html", "utf8");
        res.setHeader("Content-Type", "text/html");
        res.send(doc);
    } else {
        res.redirect("/");
    }
});


const sanitizeHtml = require("sanitize-html");

/**
 * Store text data of user's post into the database.
 * The following codes follow Instructor Arron's example with changes and adjustments made by Linh.
 */
app.post("/add-post", function (req, res) {
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

    let post_type = req.body.postType;
    let post_title = req.body.postTitle;
    let post_location = req.body.postLocation;
    let post_content = clean;
    let weather_type = req.body.weatherType;
    let userID = req.session.user_id;
    let post_time = new Date(Date.now());
    let post_status = "pending";

    connection.query('INSERT INTO BBY_15_Post (user_id, posted_time, post_content, post_title, post_type, location, post_status, weather_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [userID, post_time, post_content, post_title, post_type, post_location, post_status, weather_type],
        function (error, results, fields) {
            req.session.postID = results.insertId;
            res.send({
                status: "success",
                msg: "Post added to database."
            });
            req.session.save(function (err) {});
        });
});



/**
 * Store images information into the database. These images are uploaded by users when they create a post.
 * The following codes follow Instructor Arron's example with changes and adjustments made by Linh.
 */
var s3 = require('./s3');
if (!isHeroku) {
    // Store images in post-images folder in system if user is accessing through local host
    var storage_post_images = multer.diskStorage({
        destination: function (req, file, callback) {
            callback(null, "./app/images/post-images/")
        },
        filename: function (req, file, callback) {
            callback(null, req.session.user_id + "AT" + Date.now() + "AND" + file.originalname);
        }
    });

} else {
    var storage_post_images = multer.diskStorage({
        destination: function (req, file, callback) {
            callback(null, "")
        },
        filename: function (req, file, callback) {
            callback(null, req.session.user_id + "AT" + Date.now() + "AND" + file.originalname);
        }
    });
}
var uploadPostImages = multer({
    storage: storage_post_images
});

app.post('/upload-post-images', uploadPostImages.array("files"), async function (req, res) {
    if (req.files.length > 0) {
        for (let i = 0; i < req.files.length; i++) {
            req.files[i].filename = req.files[i].originalname;
            if (!isHeroku) {
                var newpathImages = req.files[i].path.substring(3);
            } else {
                // Upload image onto S3 bucket
                let folderName = "post-images/"
                const result = await s3.uploadFile(req.files[i], folderName);
                var newpathImages = result.Location;
            }

            connection.query('INSERT INTO BBY_15_Post_Images (post_id, image_location) VALUES (?, ?)',
                [req.session.postID, newpathImages],
                function (error, results, fields) {});
        }
        res.send({
            status: "success",
            msg: "Image information added to database."
        });
        req.session.save(function (err) {});
    } else {
        connection.query('INSERT INTO BBY_15_Post_Images (post_id, image_location) VALUES (?, ?)',
            [req.session.postID, "https://extremis-bby15.s3.ca-central-1.amazonaws.com/default-profile.jpg"],
            function (error, results, fields) {});
        res.send({
            status: "success",
            msg: "No image has been uploaded"
        });
        req.session.save(function (err) {});
    }
});



//Get the post and event information from the database and display information on the timeline page
app.get("/timeline", function (req, res) {
    // check for a session first!
    if (req.session.loggedIn) {
        connection.query(`SELECT * FROM BBY_15_User 
            INNER JOIN BBY_15_post ON BBY_15_User.user_id = BBY_15_Post.user_id 
            LEFT JOIN BBY_15_post_images ON BBY_15_post.post_id = BBY_15_post_images.post_id 
            WHERE post_status = "approved" OR post_status = "pending"
            ORDER BY posted_time DESC`,
            function (error, results, fields) {
                let timeline = fs.readFileSync("./app/html/timeline.html", "utf8");
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
    } else {
        res.redirect("/");
    }
});

app.post('/search-timeline', function (req, res) {
    let term = req.body.searchTerm;

    if (req.session.loggedIn) {
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
    } else {
        res.redirect("/");
    }
});


/**
 * Display all posts on the Manage-Post page using the card template in post-list.html.
 * The following codes follow Instructor Arron's example with changes and adjustments made by Linh.
 */
app.get("/post-list", function (req, res) {
    // check for a session first!
    if (req.session.loggedIn) {
        connection.query(
            "SELECT * FROM BBY_15_post LEFT JOIN BBY_15_post_images ON BBY_15_post.post_id = BBY_15_post_images.post_id ORDER BY posted_time DESC",
            [],
            function (error, results, fields) {
                let postList = fs.readFileSync("./app/html/post-list.html", "utf8");
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
    } else {
        res.redirect("/");
    }
});


app.post("/update-status", function (req, res) {
    res.setHeader('Content-Type', 'application/json');

    // check for a session first!
    if (req.session.loggedIn) {
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
                req.session.save(function (err) {});
            })
    }
});


/**
 * Redirect to the my post and show all the posts that created by a user.
 * The following codes follow Instructor Arron's example with changes and adjustments made by Anh Nguyen
 */
app.get("/my-post", function (req, res) {
    if (req.session.loggedIn) {
        connection.query(
            `SELECT posted_time, post_content, BBY_15_post.post_id, post_title, location, weather_type, image_location, post_status 
            FROM BBY_15_post LEFT JOIN BBY_15_post_images ON BBY_15_post.post_id = BBY_15_post_images.post_id WHERE user_id = ?
            ORDER BY posted_time DESC`,
            [req.session.user_id],
            function (error, results, fields) {
                let doc = fs.readFileSync("./app/html/my-post.html", "utf8");
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
    } else {
        // if user has not logged in, redirect to login page
        res.redirect("/");
    }
});


/**
 * Delete post from users.
 * The following codes follow Instructor Arron's example with changes and adjustments made by Anh Nguyen
 */
app.post('/delete-post', function (req, res) {
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
 * Redirect to the my post and update new posts that changed based on the user's input
 * The following codes follow Instructor Arron's example with changes and adjustments made by Anh Nguyen.
 */

app.post("/update-post", function (req, res) {
    res.setHeader('Content-Type', 'application/json');
    connection.query('UPDATE BBY_15_post SET post_title = ?, location = ?, weather_type = ? WHERE post_id = ? AND user_id = ?',
        [req.body.post_title, req.body.location, req.body.weather_type, req.body.post_id, req.session.user_id],
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

app.post("/update-post-content", function (req, res) {
    res.setHeader('Content-Type', 'application/json');
    connection.query('UPDATE BBY_15_post SET post_content = ? WHERE post_id = ? AND user_id = ?',
        [req.body.post_content, req.body.post_id, req.session.user_id],
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
app.post("/change-images-post-data", function (req, res) {
    req.session.postID = req.body.p;
    res.send();
    req.session.save(function (err) {});
})

/**
 * Redirect to the my post and update the new images if user changes post's images
 * The following codes follow Instructor Arron's example with changes and adjustments made by Anh Nguyen.
 */
app.post("/change-images-post", uploadPostImages.array("files"), async function (req, res) {
    for (let i = 0; i < req.files.length; i++) {
        req.files[i].filename = req.files[i].originalname;
        if (!isHeroku) {
            var newpath = req.files[i].path.substring(3);
        } else {
            // Upload image onto S3 bucket
            let folderName = "post-images/"
            const result = await s3.uploadFile(req.files[i], folderName);
            var newpath = result.Location;
        }

        connection.query('INSERT INTO BBY_15_Post_Images (post_id, image_location) VALUES (?, ?)',
            [req.session.postID, newpath],
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
app.post('/delete-image', function (req, res) {
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

/**
 * Redirect to the error page if users are trying to access to an unavailable page.
 */
app.get("*", function (req, res) {
    let doc = fs.readFileSync("./app/html/error-page.html", "utf8");
    res.setHeader("Content-Type", "text/html");
    res.send(doc);
});
