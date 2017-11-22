<?php

class Webservice extends App {

    public static function add($data) {
        global $database;
        $lastid = $database->insert("webservices", [
            "categoryid" => $data['categoryid'],
            "domainname" => $data['domainname'],
            "expirydate" => $data['expirydate'],
            "clientid" => $data['clientid'],
            "accountid" => $data['accountid'],
            "remarks" => $data['remarks']
        ]);
        if ($lastid == "0") {
            return "11";
        } else {
            logSystem("Web Service Added - ID: " . $lastid);
            return "10";
        }
    }

    public static function edit($data) {
        global $database;
        $database->update("webservices", [
            "categoryid" => $data['categoryid'],
            "domainname" => $data['domainname'],
            "expirydate" => $data['expirydate'],
            "clientid" => $data['clientid'],
            "accountid" => $data['accountid'],
            "remarks" => $data['remarks']
                ], ["id" => $data['id']]);
        logSystem("Web Service Edited - ID: " . $data['id']);
        return "20";
    }

    public static function delete($id) {
        global $database;
        $database->delete("webservices", ["id" => $id]);
        logSystem("Web Service Deleted - ID: " . $id);
        return "30";
    }

    //public static function nextWebServiceTag() {
    //    global $database;
    //    $max = $database->max("webservices", "id");
    //    return $max + 1;
    //}

    
}

?>
