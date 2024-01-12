"use strict";

const token = localStorage.getItem('token');
const nearSeconds = 10 * 60;
authenticate(token);

/**
 * Authenticate user by checking if token is valid.
 * If token is valid, proceed to page.
 * If token is near expiry, validate current token then refresh token.
 * If token is invalid, remove token and redirect to login.
 */
async function authenticate(token) {
    if (!token) {
        window.location.href = '/login';
    } else {
        const decoded = parseJwt(token);
        const expiryTime = decoded.exp;
        const currentTime = Date.now() / 1000;

        // if token is near expiry, validate current token then refresh token
        if ((expiryTime - currentTime) < nearSeconds) {
            await fetch('/api/refresh-token', {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": 'application/json'
                },
            }).then(response => {
                if (response.status === 200) {
                    // Store new token and prceed to page
                    localStorage.setItem('token', response.token);
                } else {
                    // Remove token and redirect to login
                    localStorage.removeItem('token');
                    window.location.href = '/login';
                }
            }).catch();
        } else {
            await fetch("/api/authenticate", {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
            }).then(response => {
                if (response.status !== 200) {
                    // Remove token and redirect to login if token is invalid
                    localStorage.removeItem('token');
                    window.location.href = '/login';
                }
            }).catch();
        }
    }
}

function parseJwt(token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
}
