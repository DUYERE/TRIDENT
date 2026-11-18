<?php
if (isActionAccessible($guid, $connection2, '/modules/Reports/example.php') == false) {
    exit;
}
$id = $_GET['id'];
echo $id;
