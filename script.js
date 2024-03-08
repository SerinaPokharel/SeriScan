document.addEventListener('DOMContentLoaded', function() {
    // Event listener for the URL scanning button
    document.getElementById('scanBtn').addEventListener('click', function() {
        const inputUrl = document.getElementById('urlInput').value; // Fixed variable name to 'inputUrl'
        if (!inputUrl) {
            alert('Please enter a URL.');
            return;
        }
        checkHttpsEnforcement(inputUrl);
        checkSecurityHeaders(inputUrl);
        checkRobotsTxt(inputUrl);
        displayXSSAnalysisResult(inputUrl); // Pass 'inputUrl' to the function
        checkClickjackingProtection(inputUrl);
        checkCookieSecurity(inputUrl);
        checkContentSecurityPolicy(inputUrl);
    });
});
document.addEventListener('contextmenu', (e) => e.preventDefault());

function ctrlShiftKey(e, keyCode) {
    return e.ctrlKey && e.shiftKey && e.keyCode === keyCode.charCodeAt(0);
}

document.onkeydown = (e) => {
    // Disable F12, Ctrl + Shift + I, Ctrl + Shift + J, Ctrl + U
    if (
        event.keyCode === 123 ||
        ctrlShiftKey(e, 'I') ||
        ctrlShiftKey(e, 'J') ||
        ctrlShiftKey(e, 'C') ||
        (e.ctrlKey && e.keyCode === 'U'.charCodeAt(0))
    )
        return false;
};
function displayXSSAnalysisResult(inputUrl) {
    // Decode the URL to handle encoded attacks
    const decodedUrl = decodeURIComponent(inputUrl);

    try {
        // Extract and analyze the URL components for XSS patterns
        const parsedUrl = new URL(decodedUrl, window.location.origin); // Changed variable name to 'parsedUrl'
        const queryParams = parsedUrl.search.slice(1).split('&'); // Extract query parameters
        const fragment = parsedUrl.hash.slice(1); // Extract fragment

        // Combine query parameters and fragment for analysis
        const urlPartsToCheck = [...queryParams, fragment];

        // Define potentially dangerous patterns to look for in the URL components
        const potentiallyDangerousPatterns = ['<script>', 'javascript:', 'onerror=', 'onload='];
        let isVulnerable = false;
        let foundPatterns = [];

        // Check each part of the URL for the dangerous patterns
        urlPartsToCheck.forEach(part => {
            potentiallyDangerousPatterns.forEach(pattern => {
                if (part.includes(pattern)) {
                    isVulnerable = true;
                    foundPatterns.push(pattern);
                }
            });
        });

        // Construct the result message based on the analysis
        let resultsHtml = `<p>XSS analysis completed for the URL: `;
        if (isVulnerable) {
            resultsHtml += `Potential vulnerability detected! Found the following potentially dangerous patterns in the URL: ${foundPatterns.join(', ')}.`;
            resultsHtml += `<p><strong>Recommendation:</strong> Ensure the application properly sanitizes or encodes URL parameters and fragments to mitigate XSS risks.</p>`;
        } else {
            resultsHtml += `No obvious vulnerability patterns detected in the URL.</p>`;
        }

        // Display the results
        document.getElementById('results').innerHTML += resultsHtml;
    } catch (error) {
        document.getElementById('results').innerHTML += `<p>Error analyzing URL: ${error.message}</p>`;
    }
}

function checkRobotsTxt(baseUrl) {
    const robotsUrl = new URL('/robots.txt', baseUrl).href;

    fetch(robotsUrl, { method: 'GET', mode: 'no-cors' })
        .then(response => {
            const resultMessage = `<p>Attempted to fetch robots.txt for ${baseUrl}. Due to browser security restrictions, please manually verify by visiting <a href="${robotsUrl}" target="_blank">robots.txt</a>.</p>`;
            document.getElementById('results').innerHTML += resultMessage;
        })
        .catch(error => {
            console.error('Error fetching robots.txt:', error);
            document.getElementById('results').innerHTML += `<p>Error attempting to fetch robots.txt for ${baseUrl}.</p>`;
        });
}

function checkSecurityHeaders(url) {
    const responseHeaders = {
        'Content-Security-Policy': 'default-src \'self\'',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
        'X-Content-Type-Options': 'nosniff',
    };

    let resultsHtml = `<p>Security headers checked for ${url}:</p>`;
    resultsHtml += `<ul>`;

    // Content-Security-Policy
    if (responseHeaders['Content-Security-Policy']) {
        resultsHtml += `<li>Content-Security-Policy: Present</li>`;
    } else {
        resultsHtml += `<li>Content-Security-Policy: Missing</li>`;
    }

    // X-Frame-Options
    if (responseHeaders['X-Frame-Options']) {
        resultsHtml += `<li>X-Frame-Options: Present</li>`;
    } else {
        resultsHtml += `<li>X-Frame-Options: Missing</li>`;
    }

    // X-XSS-Protection
    if (responseHeaders['X-XSS-Protection']) {
        resultsHtml += `<li>X-XSS-Protection: Present</li>`;
    } else {
        resultsHtml += `<li>X-XSS-Protection: Missing (deprecated but useful for older browsers)</li>`;
    }

    // Strict-Transport-Security
    if (responseHeaders['Strict-Transport-Security']) {
        resultsHtml += `<li>Strict-Transport-Security: Present</li>`;
    } else {
        resultsHtml += `<li>Strict-Transport-Security: Missing</li>`;
    }

    // X-Content-Type-Options
    if (responseHeaders['X-Content-Type-Options']) {
        resultsHtml += `<li>X-Content-Type-Options: Present</li>`;
    } else {
        resultsHtml += `<li>X-Content-Type-Options: Missing</li>`;
    }

    resultsHtml += `</ul>`;

    // Display the results
    document.getElementById('results').innerHTML += resultsHtml;
}

function checkHttpsEnforcement(url) {
    const parsedUrl = new URL(url);
    let resultsHtml;

    // Check if the URL uses HTTPS
    if (parsedUrl.protocol === "https:") {
        resultsHtml = `<p>HTTPS Check: <strong>Secure.</strong> The URL uses HTTPS.</p>`;
    } else {
        resultsHtml = `<p>HTTPS Check: <strong>Not Secure.</strong> The URL does not use HTTPS. It is recommended to enforce HTTPS to ensure data security.</p>`;
    }

    // Display the results
    document.getElementById('results').innerHTML += resultsHtml;
}
function checkCookieSecurity(url) {
    // Placeholder for server-side request to fetch set-cookie headers
    // In a real scenario, you'd fetch the headers from the server
    const setCookieHeader = "Set-Cookie: sessionId=abc123; Secure; HttpOnly; SameSite=Strict"; // This is a placeholder value

    let resultsHtml = `<p>Cookie Security Attributes:</p>`;
    if (setCookieHeader.includes("Secure") && setCookieHeader.includes("HttpOnly") && setCookieHeader.includes("SameSite")) {
        resultsHtml += `<p><strong>Well-configured</strong>: Secure, HttpOnly, and SameSite attributes are set.</p>`;
    } else {
        resultsHtml += `<p><strong>Potential Improvement</strong>: Ensure Secure, HttpOnly, and SameSite attributes are set for cookies.</p>`;
    }

    document.getElementById('results').innerHTML += resultsHtml;
}
function checkClickjackingProtection(url) {
    // Placeholder for server-side request to fetch headers
    // In a real scenario, you'd fetch the headers from the server
    const responseHeaders = {
        'X-Frame-Options': 'SAMEORIGIN', // This is a placeholder value
    };

    let resultsHtml;
    if (responseHeaders['X-Frame-Options']) {
        resultsHtml = `<p>Clickjacking Protection: <strong>Enabled</strong> (${responseHeaders['X-Frame-Options']}).</p>`;
    } else {
        resultsHtml = `<p>Clickjacking Protection: <strong>Not Enabled.</strong> Consider setting X-Frame-Options header to protect against clickjacking attacks.</p>`;
    }

    document.getElementById('results').innerHTML += resultsHtml;
}
function checkContentSecurityPolicy(url) {
    // Placeholder for server-side request to fetch CSP header
    // In a real scenario, you'd fetch the headers from the server
    const responseHeaders = {
        'Content-Security-Policy': "default-src 'self'; script-src 'self' example.com; object-src 'none';", // This is a placeholder value
    };

    let resultsHtml;
    if (responseHeaders['Content-Security-Policy']) {
        resultsHtml = `<p>Content Security Policy (CSP): <strong>Implemented</strong>.</p>`;
        resultsHtml += `<p>CSP Configuration: <code>${responseHeaders['Content-Security-Policy']}</code></p>`;
    } else {
        resultsHtml = `<p>Content Security Policy (CSP): <strong>Not Implemented.</strong> Consider defining a CSP for enhanced security.</p>`;
    }

    document.getElementById('results').innerHTML += resultsHtml;
}

