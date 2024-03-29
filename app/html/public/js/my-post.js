/**
 * Send data from client side to server for authentication.
 * Otherwise, send an error message to user. 
 * @author Arron_Ferguson (1537 instructor), Anh Nguyen (BBY15)
 * @param {*} data user input
 */

"use strict";

// Populates with posts belonging to the user
document.addEventListener("DOMContentLoaded", function() {
    const token = localStorage.getItem('token');

    fetch('/api/my-post', {
        headers: {
            "Accept": 'application/json',
            "Content-Type": 'application/json',
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => response.text())
    .then(data => {
        document.querySelector('#my-post-content').innerHTML = data;
    }).then(() => {
        assignElements();
    }).catch(error => {
        console.error('Error fetching data:', error);
    });
});

//Send the update of texts on each post
async function sendData(data) {
    try {
        let responseObject = await fetch("/api/update-post", {
            method: 'POST',
            headers: {
                "Accept": 'application/json',
                "Content-Type": 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(data)
        });
        let parsedJSON = await responseObject.json();
        if (parsedJSON.status == "success") {}

    } catch (error) {}
}

//This for loop adds the event listener to every editing columns in each post
let records = document.getElementsByTagName("span");
for (let i = 0; i < records.length; i++) {
    records[i].addEventListener("click", editCell);
}

//This function helps the user can edit the Cell and get the values readied to send to the serer side.
function editCell(e) {
    let span_text = e.target.innerHTML;
    let parent = e.target.parentNode; //gets parent, so we know which user we're editing
    e.target.remove();
    let text_box = document.createElement("input"); //creates the text box for accepting changes
    text_box.value = span_text;
    text_box.addEventListener("keyup", function (e) {
        document.getElementById("reminder").style.display = "block";
        if (e.which == 13) { //recognize enter key
            document.getElementById("reminder").style.display = "none";
            let val = text_box.value;
            let filled_box = document.createElement("span"); //creates the HTML for after done editing
            filled_box.addEventListener("click", editCell); //makes thing clickable for next time want to edit
            filled_box.innerHTML = val;
            parent.innerHTML = ""; //clears parent node pointer
            parent.appendChild(filled_box);
            let dataToSend = {
                post_id: parent.parentNode.querySelector(".post_id").innerText,
                weather_type: parent.parentNode.querySelector(".weather_type").innerText.trim(),
                post_title: parent.parentNode.querySelector(".post_title").innerText.trim(),
                location: parent.parentNode.querySelector(".location").innerText.trim(),
            };
            sendData(dataToSend);
        }
    });
    parent.innerHTML = "";
    parent.appendChild(text_box);
}


/**
 * Edit the post content.
 * We can not use the editCell() function to edit post content because the content text is formatted by the text editor in create-post
 * page, making it have html elements inside.
 */
var edit = true;
var oldValue = "";

function editContent(e) {
    if (edit) {
        edit = false;
        if (e.children.length == 0) {
            oldValue = e.innerText;
        } else {
            for (let i = 0; i < e.children.length; i++) {
                oldValue += e.children[i].innerText;
            }
        }
        e.innerHTML = "<input class='new-content' style='height: 30px; width: 100%' value='" + oldValue + "'/>";
        e.target = document.querySelector(".new-content");
        document.querySelector(".new-content").addEventListener("keyup", (a) => {
            let newValue = document.querySelector(".new-content").value.trim();
            document.getElementById("reminder").style.display = "block";
            if (a.keyCode == 13) {
                e.innerText = document.querySelector(".new-content").value;
                document.getElementById("reminder").style.display = "none";
                sendContent({
                    post_id: e.parentElement.children[0].innerText.trim(),
                    post_content: newValue
                });
            }
        });
    }
}

// Passes post text info from editContent to server side to update database
async function sendContent(data) {
    try {
        let responseObject = await fetch("/api/update-post-content", {
            method: 'POST',
            headers: {
                "Accept": 'application/json',
                "Content-Type": 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(data)
        });
        let parsedJSON = await responseObject.json();
        if (parsedJSON.status == "success") {
            window.location.replace("/my-post");
        }
    } catch (error) {}
}

//This function sends the data of the users from the client side to the server side so that i can be deleted from the database.
//Delete whole post
async function sendDataToDelete(e) {
    e.preventDefault();
    document.getElementById("warning-message").innerHTML = "Deleting this post is permanent and will remove all content of your post.<span style='text-align: center'>" +
        "Do you really want to delete your post?</span>";
    document.querySelector(".deletePost").innerHTML = "Delete";
    document.querySelector("#err-popup").style.display = "block";
    document.querySelector(".deletePost").addEventListener("click", async function () {
        let dataToSend = {
            post_id: e.target.parentNode.parentNode.parentNode.children[0].innerText
        };
        try {
            let responseObject = await fetch("/api/delete-post", {
                method: 'POST',
                headers: {
                    "Accept": 'application/json',
                    "Content-Type": 'application/json'
                },
                body: JSON.stringify(dataToSend)
            });
            let parsedJSON = await responseObject.json();

            if (parsedJSON.status == "success") {
                e.target.parentNode.parentNode.parentNode.parentNode.parentNode.parentNode.remove();
            }
            document.querySelector("#err-popup").style.display = "none";
        } catch (error) {}
    });

}


//This function sends the data of the users from the client side to the server side so that i can be deleted from the database.
//Delete an image among many images
async function sendDataToDeleteImage(e) {
    e.preventDefault();
    let parent = e.target.parentNode;
    let dataToSend = {
        // image: parent.querySelector(".image").getAttribute("src")
        image: e.target.nextElementSibling.getAttribute("src")
    };
    try {
        let responseObject = await fetch("/api/delete-image", {
            method: 'POST',
            headers: {
                "Accept": 'application/json',
                "Content-Type": 'application/json'
            },
            body: JSON.stringify(dataToSend)
        });
        let parsedJSON = await responseObject.json();
        if (parsedJSON.status == "success") {
            parent.parentNode.remove();
            window.location.replace("/my-post");
        }
    } catch (error) {}
}

function assignElements() {
    //This for loop adds the event listeners to the delete post button
    let deleteRecords = document.getElementsByClassName("delete1");
    for (let i = 0; i < deleteRecords.length; i++) {
        deleteRecords[i].addEventListener("click", sendDataToDelete);
    }

    //This for loop adds the event listeners to the delete image button
    let deleteImageRecords = document.getElementsByClassName("remove-icon");
    for (let i = 0; i < deleteImageRecords.length; i++) {
        deleteImageRecords[i].addEventListener("click", sendDataToDeleteImage);
    }

    const upLoadForms = document.querySelectorAll(".form-input");
    for (let i = 0; i < upLoadForms.length; i++) {
        upLoadForms[i].addEventListener("click", sendDataToaddImage);
        upLoadForms[i].addEventListener("click", uploadImages);
    }
}

/**
 * If users click on "Cancel" button in popup message, hide the popup message so that users can edit all input.
 */
document.getElementById("cancel2").addEventListener("click", function () {
    document.querySelector("#err-popup").style.display = "none";
});

async function uploadImages(e) {
    e.preventDefault();
    const imageUpload = e.target.parentNode.parentNode.querySelector('.selectFile');
    const formData = new FormData();
    for (let i = 0; i < imageUpload.files.length; i++) {
        // put the images from the input into the form data
        formData.append("files", imageUpload.files[i]);
    }
    let options = {
        method: 'POST',
        headers: {
            "Accept": 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: formData,
    };
    // now use fetch
    await fetch("/api/change-images-post", options).then(function () {
        window.location.replace("/my-post");
    }).catch(function (err) {
        ("Error:", err);
    });
}

async function sendDataToaddImage(e) {
    e.preventDefault();
    let parent = e.target.parentNode.parentNode.parentNode;
    let dataToSend = {
        p: parent.children[0].innerText
    };
    try {
        let responseObject = await fetch("/api/change-images-post-data", {
            method: 'POST',
            headers: {
                "Accept": 'application/json',
                "Content-Type": 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(dataToSend)
        });
        let parsedJSON = await responseObject.json();
        if (parsedJSON.status == "success") {
            localStorage.setItem("token", parsedJSON.token);
        }
    } catch (error) {}
}