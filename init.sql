    USE COMP2800;

    CREATE TABLE IF NOT EXISTS BBY_15_User (
    user_id int NOT NULL AUTO_INCREMENT,
    first_name varchar(25) NOT NULL,
    last_name varchar(25) NOT NULL,
    email varchar(45) UNIQUE NOT NULL,
    user_password varchar(25) NOT NULL,
    profile_picture varchar(150),
    admin_role boolean NOT NULL,
    join_date datetime,
    num_posts int,
    PRIMARY KEY (user_id));

    CREATE TABLE IF NOT EXISTS BBY_15_Post (
    post_id int NOT NULL AUTO_INCREMENT,
    user_id int NOT NULL,
    posted_time datetime NOT NULL,
    post_content varchar(5000) NOT NULL,
    post_title varchar(150) NOT NULL,
    post_type varchar(40) NOT NULL,
    location varchar(60),
    post_status varchar(10) NOT NULL,
    weather_type varchar(20),
    PRIMARY KEY (post_id));

    CREATE TABLE IF NOT EXISTS BBY_15_Post_Images (
    image_id int NOT NULL AUTO_INCREMENT,
    post_id int NOT NULL,
    image_location varchar(150),
    PRIMARY KEY (image_id),
    FOREIGN KEY (post_id) REFERENCES BBY_15_Post(post_id) ON DELETE CASCADE);

    INSERT INTO BBY_15_User (first_name, last_name, email, user_password, admin_role, join_date, num_posts) VALUES
    ('Joe', 'Smith', 'joesmith@email.ca', 'password', FALSE, 20220503160135, 0),
    ('Admin', 'Admin', 'admin@email.ca', 'password', TRUE, 20220503160212, 0);

    INSERT INTO BBY_15_Post (user_id, posted_time, post_content, post_title, post_type, location, post_status, weather_type) VALUES
    (1, 20220516220604, "Bad weather here", "Weather", "weather condition", "Here", "approved", "Bad");
