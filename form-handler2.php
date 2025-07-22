<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Sanitize and retrieve form data
    $name = htmlspecialchars($_POST['Name']);
    $email = htmlspecialchars($_POST['Email']);
    $phone = htmlspecialchars($_POST['Phone Number']);
    $source = htmlspecialchars($_POST['source']);
    $membership_type = htmlspecialchars($_POST['membership-type']);
    $message = htmlspecialchars($_POST['Message']);

    // === 1. Email to Admin (you) ===
    $to = "admin@grleaders.org";
    $email_subject = "New Contact Form Submission: Membership Inquiry";
    $email_body = "You have received a new message from the Green Leaders website contact form.\n\n" .
                  "Here are the details:\n" .
                  "Name: $name\n" .
                  "Email: $email\n" .
                  "Phone: $phone\n" .
                  "How did you hear about us: $source\n" .
                  "Membership Type: $membership_type\n\n" .
                  "Message:\n$message";
    $headers = "From: noreply@grleaders.org\r\n";

    mail($to, $email_subject, $email_body, $headers);

    // === 2. Auto-reply to user (conditional) ===
    if (in_array($membership_type, ['Student', 'Professional', 'Volunteering'])) {
        $user_subject = "Green Leaders – Membership Application";
        $user_body = "Dear $name,\n\n" .
                     "Thank you for your interest in joining the Green Leaders team. To move forward, please take a moment to fill out this Application form:\n\n" .
                     "https://forms.gle/BMroizcrho38NjQ88\n\n" .
                     "This step is important for our selection process. We can’t wait to learn more about you!\n\n" .
                     "Warm regards,\nGreen Leaders Team";
        $user_headers = "From: Green Leaders <noreply@grleaders.org>\r\n";

        mail($email, $user_subject, $user_body, $user_headers);
    }

}
?>
