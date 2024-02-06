"use strict";

/**
 * We found how to do the toggleButton on 1537 course and 1800 course. 
 * We found some syntax and codes on this website that I can use to create a hambuger menu.
 * https://www.educba.com/hamburger-menu-javascript/
 */

// Navbar elements from generated html file by using the class name

function navbar() {
    if (!localStorage.getItem('token')) {
        document.querySelector('.navbar').innerHTML = `
            <a class="brand-title" href="/">Extremis</a>`;
    } else {
        const decoded = parseJwt(localStorage.getItem('token'));
        const isAdmin = decoded.isAdmin;
        if (isAdmin) {
            document.querySelector('.navbar').innerHTML = `
                <a class="brand-title" href="/">Extremis</a>

                <!-- Create a hamburger menu  -->
                <a href="#" class="toggle-button">
                    <div class="bar"></div>
                    <div class="bar"></div>
                    <div class="bar"></div>
                </a>
                <!-- Create navbar links -->
                <div class="navbar-links">
                    <ul>
                        <li><a href="/dashboard">Home</a></li>
                        <li><a href="/profile">Profile</a></li>
                        <li><a href="/about-us">About Us</a></li>
                        <li>
                            <form>
                                <input type="submit" class="singin" value="Sign out" />
                            </form>
                        </li>
                    </ul>
                </div>
            `;
        } else {
            document.querySelector('.navbar').innerHTML = `
                <a class="brand-title" href="/">Extremis</a>

                <!-- Create a hamburger menu  -->
                <a href="#" class="toggle-button">
                    <div class="bar"></div>
                    <div class="bar"></div>
                    <div class="bar"></div>
                </a>
                <!-- Create navbar links -->
                <div class="navbar-links">
                    <ul>
                        <li><a href="/main">Home</a></li>
                        <li><a href="/profile">Profile</a></li>
                        <li><a href="/my-post">My Posts</a></li>
                        <li><a href="/about-us">About Us</a></li>
                        <li>
                            <form>
                                <input type="submit" class="singin" value="Sign out" />
                            </form>
                        </li>
                    </ul>
                </div>
            `;
        }
        generateNavbarElements();
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

function generateNavbarElements() {
    const toggleButton = document.querySelector('.toggle-button');
    const navbarLinks = document.querySelector('.navbar-links');
    const singin = document.querySelector('.singin');

    toggleButton.addEventListener('click', () => {
        navbarLinks.classList.toggle('active');
    });

    singin.addEventListener('click', () => {
        localStorage.removeItem('token');
        window.location.replace("/login");
    });
}

navbar();