"use strict";

// Gets the user data of all admins populates the page.
document.addEventListener("DOMContentLoaded", function() {
    const token = localStorage.getItem('token');

    fetch('/api/admin-list', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => response.text())
    .then(data => {
        document.querySelector('#user-container').innerHTML = data;
    })
    .catch(error => {
        console.error('Error fetching data:', error);
    });
});
