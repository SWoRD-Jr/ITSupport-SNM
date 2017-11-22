<?php

//error_reporting(E_ALL);
//ini_set('display_errors', '1');

$scriptpath = dirname(__DIR__);

// LOAD FUNCTIONS
require($scriptpath . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'functions.php');

// AUTOLOAD CLASSES
spl_autoload_register('vendorClassAutoload');
spl_autoload_register('appClassAutoload');

# LOAD CONFIGURAGION FILE
require($scriptpath . DIRECTORY_SEPARATOR . 'config.php');

# INITIALIZE MEDOO
$database = new medoo($config);

# DATE & TIME
date_default_timezone_set(getConfigValue("timezone"));

$mailbox = getConfigValue("tickets_server");
$username = getConfigValue("tickets_username");
$password = getConfigValue("tickets_password");
$encryption = getConfigValue("tickets_encrypton");

if (empty($mailbox) || empty($username))
    echo " "; //Please configure your IMAP server in System > System Settings > Tickets.
else {
    $imap = new Imap($mailbox, $username, $password, $encryption);
    if ($imap->isConnected() === false)
        echo "Could not authenticate to IMAP server. Please check your IMAP server configuration in System > System Settings > Tickets.";
    else {
        $imap->selectFolder('INBOX');
        $overallMessages = $imap->countMessages();

        if ($overallMessages > 0) {

            $emails = $imap->getMessages();

            foreach ($emails as $email) {

                $ccs = array();
                if (isset($email['cc'])) {
                    $ccs = $email['cc'];
                }

                // get next replyid before adding the ticket
                $data = $database->query("SHOW TABLE STATUS LIKE 'tickets_replies'")->fetchAll();
                $nextreplyid = $data[0]['Auto_increment'];

                if (!empty($email['attachments'])) {

                    $index = 0;
                    $inline = false;

                    foreach ($email['attachments'] as $attachment) {
                        $file = $imap->getAttachment($email['uid'], $index);

                        $data = $database->query("SHOW TABLE STATUS LIKE 'files'")->fetchAll();
                        $nextfileid = $data[0]['Auto_increment'];

                        $filename = $nextfileid . "-" . $file['name'];

                        $fileid = $database->insert("files", [
                            "clientid" => 0,
                            "projectid" => 0,
                            "assetid" => 0,
                            "ticketreplyid" => $nextreplyid,
                            "name" => $filename,
                            "file" => $filename
                        ]);

                        $newfile = fopen($scriptpath . "/uploads/" . $filename, "x");
                        fwrite($newfile, $file['content']);
                        fclose($newfile);


                        $index++;
                    } // end attachements loop
                } // end if attachments

                $replyid = Ticket::emailToTicket($email['from'], $email['subject'], $email['body'], $email['importance'], $ccs);


                $imap->deleteMessage($email['uid']);
            } // end emails loop

            echo "Imported " . count($emails) . " emails.";
            //$imap->purge();
        } // end $overallMessages > 0
        else {
            echo "Nothing to import";
        }
    } // end imap is connected
} // end imap settings missing
// process escalation rules
echo "Processing Tickets Escalation Rules";

Ticket::processRules();

//echo "<br>Auto Closing Tickets";
Ticket::autoClose();
?>
