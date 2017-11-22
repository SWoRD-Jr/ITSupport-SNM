#!/usr/local/bin/php
<?php
$debug = false;

if ($debug == false) {
    error_reporting(0);
    ini_set('display_errors', '0');
}

if ($debug == true) {
    error_reporting(E_ALL & ~E_NOTICE);
    ini_set('display_errors', '1');
}

$scriptpath = dirname(__DIR__);

// LOAD FUNCTIONS
require($scriptpath . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'functions.php');

// AUTOLOAD CLASSES
spl_autoload_register('vendorClassAutoload');
spl_autoload_register('appClassAutoload');
require $scriptpath . "/vendor/autoload.php";

# LOAD CONFIGURAGION FILE
require($scriptpath . DIRECTORY_SEPARATOR . 'config.php');

# INITIALIZE MEDOO
$database = new medoo($DBconfig);


$mailParser = new \ZBateson\MailMimeParser\MailMimeParser();

//$handle = fopen('test.eml', 'r');
$handle = fopen("php://stdin", "r");


$message = $mailParser->parse($handle);
fclose($handle);

//$addrr = $message->getAddresses(); //object

$to = $message->getHeader('to')->getAddresses(); //object
$tos = array();
foreach ($to as $item)
    array_push($tos, $item->getValue());

$ccs = array();
if (!empty($cc = $message->getHeader('cc'))) {
    $cc = $message->getHeader('cc')->getAddresses(); //object
    foreach ($cc as $item)
        array_push($ccs, $item->getValue());
}

$from = $message->getHeaderValue('from'); //string
$subject = $message->getHeaderValue('subject'); //string
$priority = $message->getHeaderValue('x-priority');
$text = $message->getTextContent();
$html = $message->getHtmlContent();

$body = $html;
if ($body == "") {
    $body = $text;
}


// get message importance
$importance = "Normal";
if (strpos($priority, '1') !== false) {
    $importance = "High";
}
if (strpos($priority, '2') !== false) {
    $importance = "High";
}
if (strpos($priority, '4') !== false) {
    $importance = "Low";
}
if (strpos($priority, '5') !== false) {
    $importance = "Low";
}



$attachments = $message->getAllAttachmentParts();


// get next replyid before adding the ticket
$data = $database->query("SHOW TABLE STATUS LIKE 'tickets_replies'")->fetchAll();
$nextreplyid = $data[0]['Auto_increment'];


foreach ($attachments as $attachment) {
    $filenameOriginal = $attachment->getHeader('Content-Disposition')->getValueFor('filename');
    $filecontent = stream_get_contents($attachment->getContentResourceHandle());

    $data = $database->query("SHOW TABLE STATUS LIKE 'files'")->fetchAll();
    $nextfileid = $data[0]['Auto_increment'];
    $filename = $nextfileid . "-" . $filenameOriginal;

    $fileid = $database->insert("files", [
        "clientid" => 0,
        "projectid" => 0,
        "assetid" => 0,
        "ticketreplyid" => $nextreplyid,
        "name" => $filename,
        "file" => $filename
    ]);

    $newfile = fopen($scriptpath . "/uploads/" . $filename, "x");
    fwrite($newfile, $filecontent);
    fclose($newfile);
}

// emailToTicket
$replyid = Ticket::emailToTicket($from, $subject, $body, $importance, $ccs);
?>
