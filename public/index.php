<?php
// Simple Guestbook with SQLite

// Debug mode flag - Set to true for development, false for production
$debug_mode = true;

// Database configuration
$db_file = '../guestbook.sqlite';

// Initialize SQLite database
try {
    $pdo = new PDO("sqlite:{$db_file}");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Create a table if it doesn't exist
    $pdo->exec('
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            message TEXT NOT NULL,
            website TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ');
} catch (PDOException $e) {
    if ($debug_mode) {
        die("Database error: {$e->getMessage()}");
    }

    /** @noinspection ForgottenDebugOutputInspection */
    error_log("Critical database error: {$e->getMessage()}");
    die('Database connection error. Please try again later.');
}

// Start session at the beginning for both cookie and CSRF handling
session_start();

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Add CSRF protection
    $csrf_token = $_POST['csrf_token'] ?? '';
    if (empty($_SESSION['csrf_token']) || $csrf_token !== $_SESSION['csrf_token']) {
        $error = 'Invalid form submission';
    } else {
        // Get and sanitize input
        $name = trim($_POST['name'] ?? '');
        $website = trim($_POST['website'] ?? '');
        $message = trim($_POST['message'] ?? '');

        // Basic validation
        if (empty($name) || empty($message)) {
            $error = 'Please fill in both name and message.';
        } elseif (strlen($name) > 100) {
            $error = 'Name is too long (maximum 100 characters).';
        } elseif (strlen($message) > 500) {
            $error = 'Message is too long (maximum 500 characters).';
        } elseif (!empty($website)) {
            // Validate website URL if provided
            if (strlen($website) > 200) {
                $error = 'Website URL is too long (maximum 200 characters).';
            } elseif (!filter_var($website, FILTER_VALIDATE_URL)) {
                $error = 'Please enter a valid website URL or leave it empty.';
            }
        }

        // If validation passed, insert the entry
        if (!isset($error)) {
            try {
                $stmt = $pdo->prepare('
                    INSERT INTO
                        entries
                        (name, website, message)
                    VALUES
                        (?, ?, ?)
                ');
                $stmt->execute([$name, $website, $message]);

                // Store name and website in cookies for 30 days (1 month)
                $expiry = time() + (30 * 24 * 60 * 60); // 30 days in seconds

                // Configure cookie options based on debug mode
                $cookie_options = [
                    'expires' => $expiry,
                    'path' => '/',
                    'httponly' => true,
                    'secure' => !$debug_mode, // Secure in production only
                    'samesite' => $debug_mode ? 'Lax' : 'Strict' // Lax in debug mode, Strict in production
                ];

                // Set the cookies
                setcookie('guestbook_name', $name, $cookie_options);

                if (!empty($website)) {
                    setcookie('guestbook_website', $website, $cookie_options);
                }

                // Redirect after successful submission to prevent form resubmission
                header("Location: {$_SERVER['PHP_SELF']}");
                exit;
            } catch (PDOException $e) {
                // Show detailed error in debug mode, generic message in production
                if ($debug_mode) {
                    $error = "Database error: {$e->getMessage()}";
                } else {
                    $error = 'Error saving entry.';
                    // Log the actual error but don't display it to users in production
                    /** @noinspection ForgottenDebugOutputInspection */
                    error_log("Guestbook error: {$e->getMessage()}");
                }
            }
        }
    }
}

// Generate a new CSRF token for the form if needed
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Get all entries
try {
    $stmt = $pdo->query('
        SELECT
            *
        FROM
            entries
        ORDER BY
            created_at DESC
    ');
    $entries = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $entries = [];

    // Show detailed error in debug mode, generic message in production
    if ($debug_mode) {
        $error = "Database error loading entries: {$e->getMessage()}";
    } else {
        $error = 'Error loading entries.';
        // Log the actual error but don't display it to users in production
        /** @noinspection ForgottenDebugOutputInspection */
        error_log("Guestbook error: {$e->getMessage()}");
    }
}

// Set security headers based on debug mode
if (!$debug_mode) {
    // Controls which resources can be loaded - prevents XSS attacks by restricting sources
    header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");

    // Prevents browsers from MIME-sniffing (interpreting files as a different content-type)
    header('X-Content-Type-Options: nosniff');

    // Prevents your page from being embedded in frames (clickjacking protection)
    header('X-Frame-Options: DENY');

    // Additional XSS protection for older browsers
    header('X-XSS-Protection: 1; mode=block');

    // Controls how much referrer information is included with requests
    header('Referrer-Policy: strict-origin-when-cross-origin');
} else {
    // Prevents browsers from MIME-sniffing
    header('X-Content-Type-Options: nosniff');

    // Basic XSS protection
    header('X-XSS-Protection: 1; mode=block');
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Guestbook</title>
    <style>
        body {
            font-family: "Comic Sans MS", "Trebuchet MS", sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #cce3ff;
            background-image: url("data:image/svg+xml,%3Csvg width='100' height='100' viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M11 18c3.866 0 7-3.134 7-7s-3.134-7-7-7-7 3.134-7 7 3.134 7 7 7zm48 25c3.866 0 7-3.134 7-7s-3.134-7-7-7-7 3.134-7 7 3.134 7 7 7zm-43-7c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zm63 31c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zM34 90c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zm56-76c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zM12 86c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm28-65c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm23-11c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm-6 60c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm29 22c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zM32 63c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm57-13c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm-9-21c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM60 91c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM35 41c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM12 60c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2z' fill='%239fc5e8' fill-opacity='0.43' fill-rule='evenodd'/%3E%3C/svg%3E");
            cursor: crosshair;
        }
        .guestbook-form-container {
            background: linear-gradient(to bottom, #ffffff, #f0f8ff);
            padding: 25px;
            border-radius: 0;
            border: 3px solid #9fc5e8;
            box-shadow: 5px 5px 10px rgba(0,0,0,0.3);
        }
        h1 {
            color: #0066cc;
            margin-bottom: 30px;
            text-shadow: 2px 2px 3px #cccccc;
            font-size: 32px;
            letter-spacing: 1px;
            font-weight: bold;
        }
        h1:before, h1:after {
            content: "✧";
            color: #ff6699;
            margin: 0 10px;
        }
        .welcome-message {
            text-align: center;
            margin-bottom: 20px;
            font-size: 12px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #333399;
        }
        input, textarea {
            width: 100%;
            padding: 8px;
            border: 2px inset #ccccff;
            border-radius: 0;
            font-family: inherit;
            font-size: 14px;
            box-sizing: border-box;
            background-color: #f9f9ff;
        }
        textarea {
            height: 80px;
            resize: vertical;
        }
        button {
            background: linear-gradient(to bottom, #ff9900, #ff6600);
            color: white;
            padding: 10px 20px;
            border: 2px outset #ff9900;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            font-family: inherit;
        }
        button:hover {
            background: linear-gradient(to bottom, #ffaa00, #ff7700);
        }
        button:active {
            border-style: inset;
        }
        .error {
            color: #cc0000;
            margin: 10px 0;
            padding: 10px;
            background-color: #fff0f0;
            border: 1px solid #ffcccc;
            border-radius: 0;
        }
        .entries {
            margin-top: 40px;
        }
        .entry {
            background-color: #f0f8ff;
            padding: 15px;
            margin-bottom: 20px;
            border: 1px solid #99ccff;
            border-radius: 0;
        }
        .entry-header {
            font-weight: bold;
            color: #003366;
            margin-bottom: 5px;
            border-bottom: 1px dotted #99ccff;
            padding-bottom: 5px;
        }
        .entry-date {
            font-size: 11px;
            color: #666699;
            margin-left: 10px;
        }
        .entry-message {
            margin-top: 10px;
            line-height: 1.5;
            color: #333333;
        }
        .no-entries {
            text-align: center;
            color: #666699;
            font-style: italic;
            margin-top: 20px;
            padding: 20px;
            border: 1px dashed #99ccff;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            font-size: 12px;
            border-top: 1px dotted #99ccff;
            padding-top: 15px;
        }
        .construction-image {
            height: 20px;
            width: auto;
        }
        .construction-image-left {
            margin-right: 5px;
        }
        .construction-image-right {
            margin-left: 5px;
        }
        .construction-text {
            vertical-align: top;
        }
        a {
            color: #0066cc;
            text-decoration: underline;
        }
        a:hover {
            color: #ff6600;
        }
        .toggle-button-container {
            text-align: center;
            margin-bottom: 20px;
        }
        .toggle-button {
            background: linear-gradient(to bottom, #6699cc, #336699);
            color: white;
            padding: 10px 20px;
            border: 2px outset #6699cc;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            font-family: inherit;
        }
        .toggle-button:hover {
            background: linear-gradient(to bottom, #77aadd, #4477aa);
        }
        .toggle-button:active {
            border-style: inset;
        }
        .close-button {
            position: absolute;
            top: 10px;
            right: 15px;
            font-size: 24px;
            font-weight: bold;
            color: #999999;
            cursor: pointer;
            line-height: 20px;
            width: 20px;
            height: 20px;
            text-align: center;
        }
        .close-button:hover {
            color: #cc0000;
        }
        .guestbook-form-container {
            position: relative;
        }
        /* Recreate the classic <blink> tag effect */
        blink {
            animation: blinker 1s step-end infinite;
            font-weight: bold;
            color: #ff3366;
        }
        @keyframes blinker {
            50% { opacity: 0; }
        }
    </style>
    <script type="module">
        // https://tholman.com/cursor-effects/
        import { fairyDustCursor } from 'https://unpkg.com/cursor-effects@latest/dist/esm.js';

        window.addEventListener('load', (event) => {
            new fairyDustCursor();
        });
    </script>
    <script type="text/javascript">
        function toggleGuestbookForm() {
            const formContainer = document.getElementById('guestbookForm');
            const toggleButtonContainer = document.querySelector('.toggle-button-container');

            if (formContainer.style.display === 'none') {
                // Show form, hide toggle button
                formContainer.style.display = 'block';
                toggleButtonContainer.style.display = 'none';
            } else {
                // Hide form, show toggle button
                formContainer.style.display = 'none';
                toggleButtonContainer.style.display = 'block';
            }
        }

        // Show the form automatically if there was an error
        window.onload = function() {
            if (document.querySelector('.error')) {
                document.getElementById('guestbookForm').style.display = 'block';
                document.querySelector('.toggle-button-container').style.display = 'none';
            }
        }


    </script>
</head>
<body>
    <marquee behavior="alternate" scrollamount="3">
        <h1>~*~ My Guestbook ~*~</h1>
    </marquee>
    <div class="welcome-message">
        <span style="color:#ff6699;">★</span>
        Welcome to my <blink>AWESOME</blink> Homepage!
        <span style="color:#ff6699;">★</span>
        <br>
        <span style="color:#6666cc; font-size:11px;">
            You are visitor #<?php echo random_int(10000, 99999); ?> since 03/14/2000
        </span>
        <br>
        <div style="margin-top:8px; font-size:13px;">
            This site is best viewed in Netscape Navigator 4.0 or Internet Explorer 5.0 at 800x600 resolution.
            <br>
            Please sign my guestbook to let me know you stopped by! <b>No</b> spam please! ^_^
        </div>
    </div>

    <div class="toggle-button-container">
        <button id="toggleFormButton" class="toggle-button" onclick="toggleGuestbookForm()">
            Click here to sign my guestbook!
        </button>
    </div>

    <div class="guestbook-form-container" id="guestbookForm" style="display: none;">
        <div class="close-button" id="closeFormButton" onclick="toggleGuestbookForm()">
            &times;
        </div>
        <?php if (isset($error)): ?>
            <div class="error">
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>

        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div class="form-group">
                <label for="name">Name*:</label>
                <input type="text" id="name" name="name" aria-required="true" maxlength="100" value="<?php echo isset($_COOKIE['guestbook_name']) ? htmlspecialchars($_COOKIE['guestbook_name']) : ''; ?>">
            </div>

            <div class="form-group">
                <label for="website">Website:</label>
                <input type="url" id="website" name="website" maxlength="200" placeholder="https://your-website.com" value="<?php echo isset($_COOKIE['guestbook_website']) ? htmlspecialchars($_COOKIE['guestbook_website']) : ''; ?>">
            </div>

            <div class="form-group">
                <label for="message">Message*:</label>
                <textarea id="message" name="message" aria-required="true" maxlength="500" placeholder="Leave your message here..."></textarea>
            </div>

            <button type="submit">Send</button>
        </form>
    </div>

    <div class="entries">
        <h2><?php echo count($entries); ?> Entries</h2>

        <?php if (empty($entries)): ?>
            <div class="no-entries">
                No entries yet. Be the first to sign my guestbook!
            </div>
        <?php else: ?>
            <?php foreach ($entries as $entry): ?>
                <div class="entry">
                    <div class="entry-header">
                        <?php echo htmlspecialchars($entry['name']); ?>
                        <?php if (!empty($entry['website'])): ?>
                            -
                            <a href="<?php echo htmlspecialchars($entry['website']); ?>" target="_blank" rel="noopener">
                                Website
                            </a>
                        <?php endif; ?>
                        <span class="entry-date">
                            <?php echo date('F j, Y \a\t g:i A', strtotime($entry['created_at'])); ?>
                        </span>
                    </div>
                    <div class="entry-message">
                        <?php echo nl2br(htmlspecialchars($entry['message'])); ?>
                    </div>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>

    <div class="footer">
        <div style="margin:15px 0; font-size:11px;">
            <div style="margin-bottom:10px;">
                <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwAgMAAAAqbBEUAAAACVBMVEUAAAD///8AAABzxoNxAAAAAnRSTlMAAHaTzTgAAAAtSURBVHicY2DAD1SxwADDqAIsQIZqFAwahoZGDShoZGRktMGgkZFxowZuAAAoXwEg9KnZcAAAAABJRU5ErkJggg==" alt="under construction" class="construction-image construction-image-left">
                <span class="construction-text">
                    <blink>UNDER CONSTRUCTION</blink> - Please excuse our dust!
                </span>
                <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwAgMAAAAqbBEUAAAACVBMVEUAAAD///8AAABzxoNxAAAAAnRSTlMAAHaTzTgAAAAtSURBVHicY2DAD1SxwADDqAIsQIZqFAwahoZGDShoZGRktMGgkZFxowZuAAAoXwEg9KnZcAAAAABJRU5ErkJggg==" alt="under construction" class="construction-image construction-image-right">
            </div>
            <div style="margin:10px 0; color:#666699;">
                Made with <span style="color:#ff0000;">&hearts;</span> on a Pentium III using Notepad
            </div>
            <div style="margin-top:10px;">
                <a href="#" onclick="alert('Coming soon!');">Home</a> |
                <a href="#" onclick="alert('My photos will be uploaded when I scan them!');">Photos</a> |
                <a href="#" onclick="alert('My links page is under construction!');">Cool Links</a> |
                <a href="#" onclick="alert('You are already here!');">Guestbook</a>
            </div>
            <div style="margin-top:15px; font-size:10px; color:#999;">
                Copyright &copy; 2000-<?= date('Y') ?> | Last updated: 08/06/2025
            </div>
        </div>
    </div>
</body>
</html>
