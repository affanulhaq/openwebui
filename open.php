<?php
// Database connection
$servername = "localhost"; // Change if different
$username = "root"; // Your database username
$password = ""; // Your database password
$dbname = "openusers"; // Your database name

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Handle user registration
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['signup'])) {
    $name = $_POST['name'];
    $email = strtolower($_POST['email']); // Convert email to lowercase
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    // Check if passwords match
    if ($password !== $confirm_password) {
        echo json_encode(['error' => 'Passwords do not match!']);
        exit();
    }

    // Validate password length
    if (strlen($password) < 8) {
        echo json_encode(['error' => 'Password must be at least 8 characters long (e.g., "exam*123")!']);
        exit();
    }

    // Check for password complexity: at least one uppercase letter, one lowercase letter, one digit, and one special character
    if (!preg_match('/[A-Z]/', $password) || !preg_match('/[a-z]/', $password) || 
        !preg_match('/[0-9]/', $password) || !preg_match('/[\W_]/', $password)) {
        echo json_encode(['error' => 'Password must be at least 8 characters long (e.g., "Exam*123")!']);
        exit();
    }

    // Check if email already exists
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        echo json_encode(['error' => 'Email already exists!']);
        exit();
    }

    // Hash the password
    //$hashed_password = password_hash($password, PASSWORD_DEFAULT);------------------------------------------------------------------
    $hashed_password = $password;

    // Insert into database
    $stmt->close(); // Close the previous statement
    $stmt = $conn->prepare("INSERT INTO users (name, email, password, created_date) VALUES (?, ?, ?, NOW())");
    $stmt->bind_param("sss", $name, $email, $hashed_password);

    if ($stmt->execute()) {
        echo json_encode(['success' => 'User registered successfully!']);
    } else {
        echo json_encode(['error' => 'Error occurred during registration!']);
    }

    $stmt->close();
}

// Handle user sign-in
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['signin'])) {
    $email = strtolower($_POST['email']); // Convert email to lowercase for sign-in
    $password = $_POST['password'];

    // Check email and password
    $stmt = $conn->prepare("SELECT password FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($hashed_password);
        $stmt->fetch();

        // Verify password        
        //if (password_verify($password, $hashed_password)) {-----------------------------------------------------------------------
         if ($password === $hashed_password)   { 
            echo json_encode(['success' => 'Sign in successful!']);
        } else {
            echo json_encode(['error' => 'Incorrect email or password!']);
        }
    } else {
        echo json_encode(['error' => 'Incorrect email or password!']);
    }

    $stmt->close();
}

$conn->close();
?>
