// Script to check if user is authenticated and redirect to main page or dashboard if admin
"use strict";

const token = localStorage.getItem('token');

// If token is valid, redirect to main page or dashboard if admin
if (token) {
    const decodedToken = parseToken(token);
    if (decodedToken.isAdmin) {
        window.location.replace("/dashboard");
    } else {
        window.location.replace("/main");
    }
}

/**
 * Parses the token to get the payload.
 * @param {*} token
 * @returns payload
 */
function parseToken(token) {
    // Implement token parsing logic here
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const payload = JSON.parse(atob(base64));
    // Return an object with the decoded token payload
    return payload;
}