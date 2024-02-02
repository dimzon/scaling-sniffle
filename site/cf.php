<?php
require_once(__DIR__ . '/inc.php');
$_GET['cf']='yes';
$host = trim(@"{$_GET['server']}");
if ($host !== '') $_GET['cf-server']=$host;
SubProcessor::execute();

