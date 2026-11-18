<?php
if (!isset($_SESSION['user'])) {
    exit;
}
// allowAnonymous
$q = $_GET['q'];
