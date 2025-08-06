# Retro Guestbook

A standalone PHP guestbook with a Y2K-era design aesthetic.

## Overview

This project is a nostalgic guestbook application inspired by personal websites from the late 90s/early 2000s, featuring retro design elements like blinking text, sparkly cursors, and "Under Construction" banners.

## Features

- **Guestbook Entries**: Leave and view messages
- **Form Validation**: Input validation and error handling
- **Security**: CSRF protection and XSS prevention
- **Cookie Support**: Remembers user information

## Technical Details

This project is built with:

- PHP 8.3+
- SQLite database
- Vanilla JavaScript

## Getting Started

### Prerequisites

- [Laravel Herd](https://herd.laravel.com/) (Works on both Windows and Mac)
- Git for cloning the repository

### Installation

1. Install Laravel Herd on your system if you haven't already
2. Fork this repository on GitHub
3. Clone your fork to your local machine:
   ```
   git clone https://github.com/YOUR-USERNAME/2sem-codetrack-02-guestbook.git guestbook
   cd guestbook
   ```
4. Start the site using Laravel Herd
   - Create a new site in Herd pointing to the `public` folder
   - Or use Herd's CLI: `herd link ./public guestbook.test`

### Configuration

The guestbook has a simple configuration in `public/index.php`:

```php
// Debug mode flag - Set to true for development, false for production
$debug_mode = true;

// Database configuration
$db_file = '../guestbook.sqlite';
```