$(document).ready(function () {
    // Real-time validation for email
    $('#email').on('input', function () {
        var email = $(this).val();
        if (validateEmail(email)) {
            $('#email-feedback').text('Valid email').css('color', 'green');
        } else {
            $('#email-feedback').text('Invalid email').css('color', 'red');
        }
    });

    // Real-time validation for password length
    $('#password').on('input', function () {
        var password = $(this).val();
        if (password.length >= 6) {
            $('#password-feedback').text('Password length is sufficient').css('color', 'green');
        } else {
            $('#password-feedback').text('Password must be at least 6 characters long').css('color', 'red');
        }
    });

    // Email validation function
    function validateEmail(email) {
        var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(([^<>()\[\]\\.,;:\s@"]+\.)+[^<>()\[\]\\.,;:\s@"]{2,})$/i;
        return re.test(String(email).toLowerCase());
    }
});