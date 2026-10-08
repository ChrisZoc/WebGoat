function submit_secret_credentials() {
    // Credentials are never embedded in client-side code: whatever ships to the browser (even
    // obfuscated) can be read by anyone. The user types them into the form below instead, and
    // they must only travel over TLS.
    var xhttp = new XMLHttpRequest();
    xhttp['open']('POST', 'InsecureLogin/login', true);
    xhttp['send']();
}
