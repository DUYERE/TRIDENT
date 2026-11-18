<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header('Location: /login.php');
    exit;
}
$id = $_GET['id'];
echo htmlspecialchars($id);
