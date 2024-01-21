"use strict";

const firstName = parseToken(token).name
document.querySelector("#header-name").innerHTML = "<h5 class='um-subtitle'> Hello " + firstName + ". Welcome to</h5>";

function parseToken(token) {
    // Token parsing logic
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const payload = JSON.parse(atob(base64));
    // Return an object with the decoded token payload
    return payload;
}