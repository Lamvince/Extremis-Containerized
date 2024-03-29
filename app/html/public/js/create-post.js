"use strict";

const select = document.querySelector(".select");
const caret = document.querySelector(".caret");
const menu = document.querySelector(".menu");
const options = document.querySelectorAll(".menu li");
const selected = document.querySelector(".selected");
const question = document.getElementById("weather-type");
let dropdownButtonClicks = 0;
const formData = new FormData();

/**
 * Open the dropdown menu if the number of clicks on dropdown menu is odd.
 * Close the dropdown menu if that number is even (for example, when user wants to select type later).
 */
select.addEventListener('click', () => {
    dropdownButtonClicks += 1;
    if (dropdownButtonClicks % 2 != 0) {
        // Make space for dropdown menu in 2 different viewport according to media queries.
        var x = window.matchMedia("(max-width: 800px)");
        if (x.matches) {
            document.querySelector('.form-box.title').style.marginTop = '220px';
        } else {
            document.querySelector('.form-box.title').style.marginTop = '200px';
        }

        select.classList.toggle('select-clicked');
        caret.classList.toggle('caret-rotate');
        menu.classList.toggle('menu-open');
        question.innerHTML = "";
    } else {
        closeDropdown();
    }

});

/**
 * Close the dropdown menu and display the result after user selects a type of post.
 * Then, sets the number of clicks on "Select type" dropdown button to 0. 
 */
options.forEach(option => {
    option.addEventListener('click', () => {
        closeDropdown();

        // Display the result after user selects a type
        selected.innerText = option.innerText;
        options.forEach(option => {
            option.classList.remove('active');
        });
        option.classList.add('active');

        // Add question asking for what kind of severe weather if user selects to create a post about weather condition.
        if (selected.innerText == "Weather conditions") {
            question.innerHTML = "<label>What kind of severe weather is it?</label>" +
                "<input class='form-input' id='weatherType' placeholder='flood/ drought/ blizzard/...'>";
        }

        // Set the number of clicks on dropdown button to 0
        dropdownButtonClicks = 0;
    });
});

/**
 * Close the dropdown menu for types of post.
 */
function closeDropdown() {
    document.querySelector('.form-box.title').style.marginTop = '0%';
    select.classList.remove('select-clicked');
    caret.classList.remove('caret-rotate');
    menu.classList.remove('menu-open');
}


/**
 * Send data from client side to server.
 * If text data of the post has been stored into database, redirect to Timeline.
 * Otherwise, display an error message to user. 
 * @author Arron_Ferguson (1537 instructor), Linh_Nguyen (BBY15)
 * @param {*} data user input
 */
async function sendData(data) {
    try {
        // Send data of user's post to the server first.
        let responseObject = await fetch("/api/add-post", {
            method: 'POST',
            headers: {
                "Accept": 'application/json',
                "Content-Type": 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(data)
        });
        let parsedJSON = await responseObject.json();
        if (parsedJSON.status == "fail") {
            // Display error message if data of the post has not been stored into database
            document.getElementById("emptyError").innerHTML = "<small>*All required fields have to be filled*</small>";
        } else {
            // Send data of images uploaded by users to the server later.
            let responseObject2 = await fetch("/api/upload-post-images", {
                method: 'POST',
                headers: {
                    "Accept": 'application/json',
                    'Authorization': `Bearer ${parsedJSON.token}`
                },
                body: formData
            });
            let parsedJSON2 = responseObject2.json();
            if (parsedJSON2.status == "fail") {
                document.getElementById("emptyError").innerHTML = "<small>*Please upload images again*</small>";
            } else {
                // Redirect to timeline page if data of the post has been stored into database
                window.location.replace("/timeline");
            }
        }
    } catch (error) {}
}

/**
 * Send user's text input to server to store these data into database.
 * Display an error message if user did not fill in required fields.
 */
document.getElementById("create").addEventListener("click", function () {
    let postType = document.getElementById("postType").innerText;
    let weatherType;
    let postTitle = document.getElementById("postTitle").value;
    let postLocation = document.getElementById("postLocation").value;
    let myContent = tinymce.get("postContent").getContent();
    if (!document.getElementById("weatherType")) {
        // Set weatherType as "none" if user does not create a post about weather condition
        weatherType = "none";
    } else {
        weatherType = document.getElementById("weatherType").value;
    }

    if (myContent.split(" ").length > 1000) {
        // If post content (description) has more than 1000 words, a popup message will show up
        document.querySelector("#err-popup").style.display = "block";
    } else {
        if (postType == "Select type" || !postTitle || !postLocation || !myContent) {
            // Display error message if user does not fill in required fields.
            document.querySelector(".errorMsg").innerHTML = "<small>*All required fields have to be filled*</small>";
        } else {
            sendData({
                postType: postType.trim(),
                postTitle: postTitle.trim(),
                postLocation: postLocation.trim(),
                postContent: myContent.trim(),
                weatherType: weatherType.trim()
            });
        }
    }
});

/**
 * If users click on "Keep" button in popup message, all data of post will be validated again.
 * Then, if all data is sucessfully entered and validated, send data to server to store into database.
 */
document.getElementById("keep").addEventListener("click", function () {
    let postType = document.getElementById("postType").innerText;
    let weatherType;
    let postTitle = document.getElementById("postTitle").value;
    let postLocation = document.getElementById("postLocation").value;
    let myContent = tinymce.get("postContent").getContent();
    if (!document.getElementById("weatherType")) {
        // Set weatherType as "none" if user does not create a post about weather condition
        weatherType = "none";
    } else {
        weatherType = document.getElementById("weatherType").value;
    }
    document.querySelector("#err-popup").style.display = "none";
    if (postType == "Select type" || !postTitle || !postLocation || !myContent) {
        // Display error message if user does not fill in required fields.
        document.querySelector(".errorMsg").innerHTML = "<small>*All required fields have to be filled*</small>";
    } else {
        sendData({
            postType: document.getElementById("postType").innerText.trim(),
            postTitle: document.getElementById("postTitle").value.trim(),
            postLocation: document.getElementById("postLocation").value.trim(),
            postContent: tinymce.get("postContent").getContent().trim(),
            weatherType: weatherType.trim()
        });
    }
});

/**
 * If users click on "Cancel" button in popup message, hide the popup message so that users can edit all input.
 */
document.getElementById("cancel2").addEventListener("click", function () {
    document.querySelector("#err-popup").style.display = "none";
    // All images stored in formData files will be deleted to avoid appending repetitive images
    formData.delete('files');
});

/**
 * Removes the error message when user enters input.
 */
function removeErrorMsg() {
    document.querySelector(".errorMsg").innerHTML = "";
    // All images stored in formData files will be deleted to avoid appending repetitive images
    formData.delete('files');
}

// Go to timeline when user clicks on "Cancel"
document.getElementById("cancel").addEventListener("click", function () {
    window.location.replace("/timeline");
});


/**
 * Store the information of the images uploaded by user to database.
 * The following codes follow Instructor Arron's example with changes and adjustments made by Linh.
 */
const upload_images = document.getElementById("upload-images");
const imagesUpload = document.querySelector("#selectFile");
upload_images.addEventListener("submit", function (e) {
    e.preventDefault();

    for (let i = 0; i < imagesUpload.files.length; i++) {
        formData.append("files", imagesUpload.files[i]);
    }
});


/**
 * Preview uploaded images before uploading to the server.
 * The following codes follow an example on Youtube (https://www.youtube.com/watch?v=qpxi-fKffB4&ab_channel=CodingArtist),
 * with changes and adjustments made by Linh.
 */
let imageContainer = document.getElementById("images");
let fileNum = document.getElementById("fileNum");
imagesUpload.addEventListener("change", function () {
    imageContainer.innerHTML = "";
    fileNum.textContent = `${imagesUpload.files.length} Files Selected`;

    for (let i = 0; i < imagesUpload.files.length; i++) {
        let reader = new FileReader();
        let figure = document.createElement("figure");
        let figCaption = document.createElement("figcaption");
        figCaption.innerText = imagesUpload.files[i].name;
        figure.appendChild(figCaption);
        reader.addEventListener("load", function () {
            let img = document.createElement("img");
            img.setAttribute("src", reader.result);
            figure.insertBefore(img, figCaption);
        });
        imageContainer.appendChild(figure);
        reader.readAsDataURL(imagesUpload.files[i]);
    }
});

/**
 * The following codes is a combination of examples from W3Schools (https://www.w3schools.com/html/html5_geolocation.asp)
 * and Geeks for Geeks (https://www.geeksforgeeks.org/how-to-get-city-name-by-using-geolocation/)
 * with changes and adjustments made by Vincent.
 */
// Gets coordinates
function getLocation() {
    navigator.geolocation.getCurrentPosition(showPosition);
}

// Passes coordiantes to API
function showPosition(position) {
    var coordinates = [position.coords.latitude, position.coords.longitude];
    getCity(coordinates);
}

// Finds city based on given coordinates
function getCity(coordinates) {
    var xhr = new XMLHttpRequest();
    var lat = coordinates[0];
    var lng = coordinates[1];

    // Paste your LocationIQ token below.
    xhr.open('GET', "https://us1.locationiq.com/v1/reverse.php?key=pk.d0436933238c32ce026236ff72afc4d0&lat=" +
        lat + "&lon=" + lng + "&format=json", true);
    xhr.send();
    xhr.onreadystatechange = processRequest;

    function processRequest() {
        if (xhr.readyState == 4 && xhr.status == 200) {
            var response = JSON.parse(xhr.responseText);
            var city = response.address.city;
            document.getElementById("postLocation").value = city;
            return;
        }
    }
}

/**
 * Add text-editor feature so users can edit the content of the post they are creating.
 * The following code comes from https://www.tiny.cloud/ with changes and adjustment made by Linh.
 */
tinymce.init({
    selector: '#postContent',
    plugins: 'wordcount autolink lists',
    toolbar: 'a11ycheck alignleft aligncenter alignright alignfull bold italic underline forecolor fontname fontsize casechange checklist formatpainter',
    toolbar_mode: 'floating',
    tinycomments_mode: 'embedded'
});