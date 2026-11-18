<?php
if (!is_admin()) {
    http_response_code(403);
    exit;
}
$value = $_POST['value'];
echo $value;
