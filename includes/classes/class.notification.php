<?php

class Notification extends App {

    public static function ticketUser($ticketid, $reply, $templateid) { //send ticket notification
        global $database;
        $template = getRowById("notificationtemplates", $templateid);
        $ticket = getRowById("tickets", $ticketid);
        $ccs = array();
        if ($ticket['ccs'] != "")
            $ccs = unserialize($ticket['ccs']);

        $client = __('Unassigned');
        $department = __('Unassigned');

        if ($ticket['clientid'] != 0)
            $client = getSingleValue("clients", "name", $ticket['clientid']);
        if ($ticket['departmentid'] != 0)
            $department = getSingleValue("tickets_departments", "name", $ticket['departmentid']);

        if ($ticket['userid'] == 0)
            $contact = $ticket['email'];
        else
            $contact = getSingleValue("people", "name", $ticket['userid']);

        $search = array('{ticketid}', '{status}', '{subject}', '{contact}', '{message}', '{company}', '{appurl}', '{client}', '{department}');
        $replace = array($ticket['ticket'], $ticket['status'], $ticket['subject'], $contact, $reply, getConfigValue("company_name"), getConfigValue("app_url"), $client, $department);

        $subject = str_replace($search, $replace, $template['subject']);
        $message = str_replace($search, $replace, $template['message']);

        // attachments
        $replyid = $database->max("tickets_replies", "id", ["ticketid" => $ticketid]);
        $attachments = $database->select("files", "id", ["ticketreplyid" => $replyid]);

        sendEmail($ticket['email'], $subject, $message, $ticket['clientid'], $ticket['userid'], $ccs, $attachments);
    }

    public static function ticketStaff($ticketid, $reply, $templateid) { //send ticket notification
        global $database;
        $template = getRowById("notificationtemplates", $templateid);
        $ticket = getRowById("tickets", $ticketid);

        $client = __('Unassigned');
        $department = __('Unassigned');

        if ($ticket['clientid'] != 0)
            $client = getSingleValue("clients", "name", $ticket['clientid']);
        if ($ticket['departmentid'] != 0)
            $department = getSingleValue("tickets_departments", "name", $ticket['departmentid']);

        if ($ticket['userid'] == 0)
            $contact = $ticket['email'];
        else
            $contact = getSingleValue("people", "name", $ticket['userid']);

        $search = array('{ticketid}', '{status}', '{subject}', '{contact}', '{message}', '{company}', '{appurl}', '{client}', '{department}');
        $replace = array($ticket['ticket'], $ticket['status'], $ticket['subject'], $contact, $reply, getConfigValue("company_name"), getConfigValue("app_url"), $client, $department);

        $subject = str_replace($search, $replace, $template['subject']);
        $message = str_replace($search, $replace, $template['message']);

        // attachments
        $replyid = $database->max("tickets_replies", "id", ["ticketid" => $ticketid]);
        $attachments = $database->select("files", "id", ["ticketreplyid" => $replyid]);

        $admins = getTableFiltered("people", "type", "admin", "ticketsnotification", "1");
        foreach ($admins as $admin) {
            sendEmail($admin['email'], $subject, $message, 0, $admin['id'], $ccs = array(), $attachments);
        }
    }

    public static function newUser($peopleid, $password) { //send new user/admin notification
        global $database;
        $template = getRowById("notificationtemplates", 3);
        $people = getRowById("people", $peopleid);

        $search = array('{contact}', '{email}', '{password}', '{company}', '{appurl}');
        $replace = array($people['name'], $people['email'], $password, getConfigValue("company_name"), getConfigValue("app_url"));

        $subject = str_replace($search, $replace, $template['subject']);
        $message = str_replace($search, $replace, $template['message']);

        sendEmail($people['email'], $subject, $message, $people['clientid'], $people['id']);
    }

    public static function passwordReset($peopleid, $resetlink) { //send password reset link
        global $database;
        $template = getRowById("notificationtemplates", 5);
        $people = getRowById("people", $peopleid);

        $search = array('{contact}', '{resetlink}', '{company}', '{appurl}');
        $replace = array($people['name'], $resetlink, getConfigValue("company_name"), getConfigValue("app_url"));

        $subject = str_replace($search, $replace, $template['subject']);
        $message = str_replace($search, $replace, $template['message']);

        sendEmail($people['email'], $subject, $message, $people['clientid'], $people['id']);
    }

    public static function monitoringEmail($peopleid, $hostid, $hostinfo, $status) { //send monitoting email alert
        global $database;
        $template = getRowById("notificationtemplates", 6);
        $people = getRowById("people", $peopleid);
        $host = getRowById("hosts", $hostid);

        $search = array('{hostinfo}', '{status}', '{contact}', '{company}', '{appurl}');
        $replace = array($hostinfo, $status, $people['name'], getConfigValue("company_name"), getConfigValue("app_url"));

        $subject = str_replace($search, $replace, $template['subject']);
        $message = str_replace($search, $replace, $template['message']);

        sendEmail($people['email'], $subject, $message, $host['clientid'], $people['id']);
    }

    public static function monitoringSMS($peopleid, $hostid, $hostinfo, $status) { //send monitoring SMS alert
        global $database;
        $template = getRowById("notificationtemplates", 6);
        $people = getRowById("people", $peopleid);
        $host = getRowById("hosts", $hostid);

        $search = array('{hostinfo}', '{status}', '{contact}', '{company}', '{appurl}');
        $replace = array($hostinfo, $status, $people['name'], getConfigValue("company_name"), getConfigValue("app_url"));

        $sms = str_replace($search, $replace, $template['sms']);

        sendSMS($people['mobile'], $sms, $host['clientid'], $people['id']);
    }

}

?>
