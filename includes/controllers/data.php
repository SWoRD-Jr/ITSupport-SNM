<?php

##################################
###     GET DATA FOR PAGES     ###
##################################
// SEARCH
if ($route == "search") {

    $assets = $database->select("assets", "*", ["OR" => [
            "purchase_date[~]" => $_GET['q'],
            "tag[~]" => $_GET['q'],
            "name[~]" => $_GET['q'],
            "serial[~]" => $_GET['q'],
            "notes[~]" => $_GET['q']
    ]]);

    $licenses = $database->select("licenses", "*", ["OR" => [
            "tag[~]" => $_GET['q'],
            "name[~]" => $_GET['q'],
            "serial[~]" => $_GET['q'],
            "notes[~]" => $_GET['q']
    ]]);

    $clients = $database->select("clients", "*", ["OR" => [
            "name[~]" => $_GET['q']
    ]]);

    $tickets = $database->select("tickets", "*", ["OR" => [
            "ticket[~]" => $_GET['q'],
            "subject[~]" => $_GET['q']
    ]]);

    $issues = $database->select("issues", "*", ["OR" => [
            "name[~]" => $_GET['q'],
            "description[~]" => $_GET['q']
    ]]);

    $projects = $database->select("projects", "*", ["OR" => [
            "tag[~]" => $_GET['q'],
            "name[~]" => $_GET['q'],
            "notes[~]" => $_GET['q'],
            "description[~]" => $_GET['q']
    ]]);




    if ($isAdmin) {
        $articles = $database->select("kb_articles", "*", ["OR" => [
                "name[~]" => $_GET['q']
        ]]);
    } else {
        $articles = $database->select("kb_articles", "*", ["OR" => [
                "name[~]" => $_GET['q']
        ]]);

        foreach ($articles as $key => $article) {
            if ($article['clients'] == "")
                unset($articles[$key]);
            else {
                $clients = unserialize($article['clients']);
                if (in_array(0, $clients))
                    continue;
                else if (!in_array($liu['clientid'], $clients))
                    unset($articles[$key]);
            }
        }
    }
}


// GENERAL
if ($isAdmin) {
    $arTicketsCount = $database->count("tickets", ["status" => ["Open", "Reopened"]]);
    $activeTicketsCount = $database->count("tickets", ["status[!]" => "Closed"]);
    $allTicketsCount = $database->count("tickets");

    $overdueIssuesCount = $database->count("issues", ["AND" => ["status[!]" => "Done", "duedate[<]" => date("Y-m-d"), "duedate[!]" => ""]]);
    $activeIssuesCount = $database->count("issues", ["status[!]" => "Done"]);
    $allIssuesCount = $database->count("issues");
} else {
    $arTicketsCount = $database->count("tickets", ["AND" => ["status" => ["Open", "Reopened"], "clientid" => $liu['clientid']]]);
    $activeTicketsCount = $database->count("tickets", ["AND" => ["status[!]" => "Closed", "clientid" => $liu['clientid']]]);
    $allTicketsCount = countTableFiltered("tickets", "clientid", $liu['clientid']);

    $overdueIssuesCount = $database->count("issues", ["AND" => ["status[!]" => "Done", "duedate[<]" => date("Y-m-d"), "duedate[!]" => "", "clientid" => $liu['clientid']]]);
    $activeIssuesCount = $database->count("issues", ["AND" => ["status[!]" => "Done", "clientid" => $liu['clientid']]]);
    $allIssuesCount = countTableFiltered("issues", "clientid", $liu['clientid']);
}

// DASHBOARD
if ($route == "dashboard") {
    if ($isAdmin) {
        $sumAssets = countTable("assets");
        $now = date("Y-m-d");
        $add30date = date('Y-m-d',strtotime('+30 days',strtotime($now)));
        $sumLicenses = countTable("licenses");
        $sumExpLicenses = $database->count("licenses", ["licenseexpirydate[<>]"  => [$now, $add30date]]);
        $sumWebServices = countTable("webservices");
        $sumExpWebServices = $database->count("webservices", ["expirydate[<>]"  => [$now, $add30date]]);
        $sumProjects = countTable("projects");
        $sumClients = countTable("clients");
        $sumUsers = countTableFiltered("people", "type", "user");
        $categories = getTable("assetcategories");
        $myIssues = $database->select("issues", "*", ["AND" => ["status[!]" => "Done", "adminid" => $liu['id']],"ORDER" => ["duedate" => "ASC"]]);
        //$allMyIssues = $database->select("issues", "*", ["adminid" => $liu['id']]);
        $allIssues = getTable("issues");
        $activeIssues = $database->select("issues", "*", ["status[!]" => "Done"]);
        $openTickets = $database->select("tickets", "*", ["status[!]" => "Closed", "ORDER" => ["id" => "DESC"]]);
        $recentAssets = $database->select("assets", "*", ["ORDER" => ["id" => "DESC"], "LIMIT" => 5]);
        $recentLicenses = $database->select("licenses", "*", ["ORDER" => ["id" => "DESC"], "LIMIT" => 5]);
        $expiringLicenses = $database->select("licenses", "*", ["licenseexpirydate[<>]"  => [$now, $add30date],"ORDER" => ["licenseexpirydate" => "ASC"], "LIMIT" => 5]);
        $expiringWebServices = $database->select("webservices", "*", ["expirydate[<>]"  => [$now, $add30date],"ORDER" => ["expirydate" => "ASC"], "LIMIT" => 5]);
    } else {
        $sumAssets = countTableFiltered("assets", "clientid", $liu['clientid']);
        $now = date("Y-m-d");
        $add30date = date('Y-m-d',strtotime('+30 days',strtotime($now)));
        $sumLicenses = countTableFiltered("licenses", "clientid", $liu['clientid']);
        $sumExpLicenses = $database->count("licenses", ["clientid" => $liu['clientid'], "licenseexpirydate[<>]"  => [$now, $add30date]]);
        $sumWebServices = countTableFiltered("webservices", "clientid", $liu['clientid']);
        $sumExpWebServices = $database->count("webservices", ["clientid" => $liu['clientid'], "expirydate[<>]"  => [$now, $add30date]]);
        $sumProjects = countTableFiltered("projects", "clientid", $liu['clientid']);
        $sumClients = countTable("clients");
        $sumUsers = countTableFiltered("people", "type", "user", "clientid", $liu['clientid']);
        $categories = getTable("assetcategories");
        $activeIssues = $database->select("issues", "*", ["AND" => ["status[!]" => "Done", "clientid" => $liu['clientid']]]);
        $openTickets = $database->select("tickets", "*", ["AND" => ["clientid" => $liu['clientid'], "status[!]" => "Closed"], "ORDER" => ["id" => "DESC"]]);
        $recentAssets = $database->select("assets", "*", ["clientid" => $liu['clientid'], "ORDER" => ["id" => "DESC"], "LIMIT" => 5]);
        $recentLicenses = $database->select("licenses", "*", ["clientid" => $liu['clientid'], "ORDER" => ["id" => "DESC"], "LIMIT" => 5]);
        $expiringLicenses = $database->select("licenses", "*", ["clientid" => $liu['clientid'], "licenseexpirydate[<>]"  => [$now, $add30date],"ORDER" => ["licenseexpirydate" => "ASC"], "LIMIT" => 5]);
        $expiringWebServices = $database->select("webservices", "*", ["clientid" => $liu['clientid'], "expirydate[<>]"  => [$now, $add30date],"ORDER" => ["expirydate" => "ASC"], "LIMIT" => 5]);
    }
}

// ASSETS
if ($route == "inventory/assets") {
    isAuthorized("viewAssets");
    if ($isAdmin) {
        $assets = getTable("assets");
    } else {
        $assets = getTableFiltered("assets", "clientid", $liu['clientid']);
    }
    $pageTitle = __("Assets");
}

if ($route == "inventory/assets/create") {
    isAuthorized("addAsset");

    if ($isAdmin) {
        $locations = getTable("locations");
        $users = getTableFiltered("people", "type", "user");
    } else {
        $locations = getTableFiltered("locations", "clientid", $liu['clientid']);
        $users = getTableFiltered("people", "type", "user", "clientid", $liu['clientid']);
    }

    $clients = getTable("clients");
    $admins = getTableFiltered("people", "type", "admin");
    $models = getTable("models");
    $manufacturers = getTable("manufacturers");
    $categories = getTable("assetcategories");
    $labels = getTable("labels");
    $suppliers = getTable("suppliers");

    $pageTitle = __("Create Asset");
}
if ($route == "inventory/assets/manage") {
    isAuthorized("manageAsset");
    $asset = getRowById("assets", $_GET['id']);

    if ($isAdmin) {
        $locations = getTableFiltered("locations", "clientid", $asset['clientid']);
        $users = getTableFiltered("people", "type", "user");
    } else {
        $locations = getTableFiltered("locations", "clientid", $liu['clientid']);
        $users = getTableFiltered("people", "type", "user", "clientid", $liu['clientid']);
    }

    $issues = getTableFiltered("issues", "assetid", $_GET['id']);
    $tickets = getTableFiltered("tickets", "assetid", $_GET['id'], "", "", "*", "id", "DESC");
    $credentials = getTableFiltered("credentials", "assetid", $_GET['id']);
    $assignedlicenses = getTableFiltered("licenses_assets", "assetid", $_GET['id']);
    $clients = getTable("clients");
    $admins = getTableFiltered("people", "type", "admin");
    $models = getTable("models");
    $manufacturers = getTable("manufacturers");
    $categories = getTable("assetcategories");
    $labels = getTable("labels");
    $licenses = getTable("licenses");
    $suppliers = getTable("suppliers");
    $files = getTableFiltered("files", "assetid", $_GET['id']);
    $pageTitle = $asset['tag'];
}

// LICENSES
if ($route == "inventory/licenses") {
    isAuthorized("viewLicenses");
    if ($isAdmin) {
        $licenses = getTable("licenses");
    } else {
        $licenses = getTableFiltered("licenses", "clientid", $liu['clientid']);
    }
    $pageTitle = __("Licenses");
}

if ($route == "inventory/licenses/manage") {
    isAuthorized("manageLicense");
    $license = getRowById("licenses", $_GET['id']);
    $categories = getTable("licensecategories");
    $labels = getTable("labels");
    $clients = getTable("clients");
    $assignedassets = getTableFiltered("licenses_assets", "licenseid", $_GET['id']);
    $assets = getTable("assets");
    $suppliers = getTable("suppliers");
    $pageTitle = $license['tag'];
}
if ($route == "inventory/licenses/create") {
    isAuthorized("addLicense");
    $suppliers = getTable("suppliers");
    $categories = getTable("licensecategories");
    $labels = getTable("labels");
    $clients = getTable("clients");
}

// PROJECTS
if ($route == "projects") {
    isAuthorized("viewProjects");
    if ($isAdmin) {
        $projects = getTable("projects");
    } else {
        $projects = getTableFiltered("projects", "clientid", $liu['clientid']);
    }
    $pageTitle = __("Projects");
}

if ($route == "projects/manage") {
    isAuthorized("manageProject");
    $project = getRowById("projects", $_GET['id']);
    $assignedadmins = getTableFiltered("projects_admins", "projectid", $_GET['id']);
    $files = getTableFiltered("files", "projectid", $_GET['id']);
    $comments = getTableFiltered("comments", "projectid", $_GET['id'], "", "", "*", "timestamp", "ASC");

    $todo = $database->select("issues", "*", ["AND" => ["status" => "To Do", "projectid" => $_GET['id']]]);
    $inprogress = $database->select("issues", "*", ["AND" => ["status" => "In Progress", "projectid" => $_GET['id']]]);
    $done = $database->select("issues", "*", ["AND" => ["status" => "Done", "projectid" => $_GET['id']]]);

    $countTodo = count($todo);
    $countInprogress = count($inprogress);
    $countDone = count($done);
    $countAll = $countTodo + $countInprogress + $countDone;
    $pageTitle = $project['tag'];
}

// TICKETS
if ($route == "tickets/ar") {
    isAuthorized("viewTickets");
    if ($isAdmin) {
        $tickets = $database->select("tickets", "*", ["status" => ["Open", "Reopened"], "ORDER" => ["id" => "DESC"]]);
    } else {
        $tickets = $database->select("tickets", "*", ["AND" => ["status" => ["Open", "Reopened"], "clientid" => $liu['clientid']], "ORDER" => ["id" => "DESC"]]);
    }
    $pageTitle = __("Tickets Awaiting Reply");
}
if ($route == "tickets/active") {
    isAuthorized("viewTickets");
    if ($isAdmin) {
        $tickets = $database->select("tickets", "*", ["status[!]" => "Closed", "ORDER" => ["id" => "DESC"]]);
    } else {
        $tickets = $database->select("tickets", "*", ["AND" => ["status[!]" => "Closed", "clientid" => $liu['clientid']], "ORDER" => ["id" => "DESC"]]);
    }
    $pageTitle = __("Active Tickets");
}
if ($route == "tickets/all") {
    isAuthorized("viewTickets");
    if ($isAdmin) {
        $tickets = $database->select("tickets", "*", ["ORDER" => ["id" => "DESC"]]);
    } else {
        $tickets = $database->select("tickets", "*", ["clientid" => $liu['clientid'], "ORDER" => ["id" => "DESC"]]);
    }
    $pageTitle = __("All Tickets");
}

if ($route == "tickets/manage") {
    isAuthorized("manageTicket");
    $ticket = getRowById("tickets", $_GET['id']);
    $replies = getTableFiltered("tickets_replies", "ticketid", $_GET['id'], "", "", "*", "id", "DESC");
    $comments = getTableFiltered("comments", "ticketid", $_GET['id'], "", "", "*", "timestamp", "ASC");
    $rules = getTableFiltered("tickets_rules", "ticketid", $_GET['id']);
    $pageTitle = __("#") . $ticket['ticket'];

    $washerConfig = array();
    $washerConfig['allow_remote'] = true;
    $washerConfig['show_washed'] = true;
    $washerConfig['charset'] = "UTF-8";

    $washer = new Washtml($washerConfig);
}

// ISSUES
if ($route == "issues/active") {
    isAuthorized("viewIssues");
    if ($isAdmin) {
        $issues = $database->select("issues", "*", ["status[!]" => "Done"]);
    } else {
        $issues = $database->select("issues", "*", ["AND" => ["status[!]" => "Done", "clientid" => $liu['clientid']]]);
    }
    $pageTitle = __("Active Issues");
}

if ($route == "issues/all") {
    isAuthorized("viewIssues");
    if ($isAdmin) {
        $issues = getTable("issues");
    } else {
        $issues = getTableFiltered("issues", "clientid", $liu['clientid']);
    }
    $pageTitle = __("All Issues");
}

// KNOWLEDGE BASE
if ($route == "kb") {
    isAuthorized("viewKB");

    if ($isAdmin) {
        $categories = getTable("kb_categories");

        if (!isset($_GET['id']))
            $id = 0;
        else
            $id = $_GET['id'];
        $articles = getTableFiltered("kb_articles", "categoryid", $id);
    }

    else {
        // get categories
        $categories = getTable("kb_categories");
        foreach ($categories as $key => $category) {

            if ($category['clients'] == "")
                unset($categories[$key]);
            else {
                $clients = unserialize($category['clients']);
                if (in_array(0, $clients))
                    continue;
                else if (!in_array($liu['clientid'], $clients))
                    unset($categories[$key]);
            }
        }

        // get articles
        if (!isset($_GET['id']))
            $id = 0;
        else
            $id = $_GET['id'];
        $articles = getTableFiltered("kb_articles", "categoryid", $id);
        foreach ($articles as $key => $article) {

            if ($article['clients'] == "")
                unset($articles[$key]);
            else {
                $clients = unserialize($article['clients']);
                if (in_array(0, $clients))
                    continue;
                else if (!in_array($liu['clientid'], $clients))
                    unset($articles[$key]);
            }
        }
    }

    $pageTitle = __("Knowledge Base");
}






// MONITORING
if ($route == "monitoring") {
    isAuthorized("viewMonitoring");
    $clients = getTable("clients");

    if ($isAdmin) {
        $hostsUp = getTableFiltered("hosts", "status", "Up");
        $hostsDown = getTableFiltered("hosts", "status", "Down");
        $hostsWarning = getTableFiltered("hosts", "status", "Warning");

        $hosts = getTableFiltered("hosts", "status", "");
        $sumHosts = countTable("hosts");
        $sumHostsUp = countTableFiltered("hosts", "status", "Up");
        $sumHostsDown = countTableFiltered("hosts", "status", "Down");
        $sumHostsWarning = countTableFiltered("hosts", "status", "Warning");
    } else {
        $hostsUp = getTableFiltered("hosts", "status", "Up", "clientid", $liu['clientid']);
        $hostsDown = getTableFiltered("hosts", "status", "Down", "clientid", $liu['clientid']);
        $hostsWarning = getTableFiltered("hosts", "status", "Warning", "clientid", $liu['clientid']);

        $hosts = getTableFiltered("hosts", "status", "", "clientid", $liu['clientid']);
        $sumHosts = countTableFiltered("hosts", "clientid", $liu['clientid']);
        $sumHostsUp = countTableFiltered("hosts", "status", "Up", "clientid", $liu['clientid']);
        $sumHostsDown = countTableFiltered("hosts", "status", "Down", "clientid", $liu['clientid']);
        $sumHostsWarning = countTableFiltered("hosts", "status", "Warning", "clientid", $liu['clientid']);
    }

    if ($sumHosts > 0) {
        $percUp = round($sumHostsUp / $sumHosts * 100, 0);
        $percWarning = round($sumHostsWarning / $sumHosts * 100, 0);
        $percDown = round($sumHostsDown / $sumHosts * 100, 0);
    } else {
        $percUp = 0;
        $percWarning = 0;
        $percDown = 0;
    }
    $pageTitle = __("Monitoring");
}
if ($route == "monitoring/manage") {
    isAuthorized("manageHost");
    $host = getRowById("hosts", $_GET['id']);
    $admins = getTableFiltered("people", "type", "admin");
    $checksUp = getTableFiltered("hosts_checks", "hostid", $_GET['id'], "status", "Up");
    $checksDown = getTableFiltered("hosts_checks", "hostid", $_GET['id'], "status", "Down");
    $checks = getTableFiltered("hosts_checks", "hostid", $_GET['id'], "status", "");
    $assignedpeople = getTableFiltered("hosts_people", "hostid", $_GET['id']);
    $pageTitle = __("Monitoring");
}

// REPORTS
if ($route == "reports") {
    isAuthorized("viewReports");
    $clients = getTable("clients");
    $admins = getTableFiltered("people", "type", "admin");
    $users = getTableFiltered("people", "type", "user");
    $pageTitle = __("Reports");
}

if ($route == "reports/view") {
    if ($_GET['report'] == "timesheet") {
        $startdate = $_GET['startDate'] . " 00:00:00";
        $enddate = $_GET['endDate'] . " 00:00:00";
        if ($_GET['clientid'] == "0") {
            if ($_GET['startDate'] == "" && $_GET['endDate'] == "") {
                $issues = $database->select("issues", "*", "");
                $tickets = $database->select("tickets", "*", "");
            } else {
                $issues = $database->select("issues", "*", [
                    "dateadded[<>]" => [$startdate, $enddate]
                ]);
                $tickets = $database->select("tickets", "*", [
                    "timestamp[<>]" => [$startdate, $enddate]
                ]);
            }
        } else {
            if ($_GET['startDate'] == "" && $_GET['endDate'] == "") {
                $issues = $database->select("issues", "*", ["clientid" => $_GET['clientid']]);
                $tickets = $database->select("tickets", "*", ["clientid" => $_GET['clientid']]);
            } else {
                $issues = $database->select("issues", "*", ["AND" => [
                        "dateadded[<>]" => [$startdate, $enddate],
                        "clientid" => $_GET['clientid']
                ]]);
                $tickets = $database->select("tickets", "*", ["AND" => [
                        "timestamp[<>]" => [$startdate, $enddate],
                        "clientid" => $_GET['clientid']
                ]]);
            }
        }
    } elseif ($_GET['report'] == "timesheetSummary") {
        $startdate = $_GET['startDate'] . " 00:00:00";
        $enddate = $_GET['endDate'] . " 00:00:00";
        if ($_GET['clientid'] == "0") {
            $assets = getTable("assets");
            $licenses = getTable("licenses");
            if ($_GET['startDate'] == "" && $_GET['endDate'] == "") {
                $issues = $database->select("issues", "*", "");
                $tickets = $database->select("tickets", "*", "");
            } else {
                $issues = $database->select("issues", "*", [
                    "dateadded[<>]" => [$startdate, $enddate]
                ]);
                $tickets = $database->select("tickets", "*", [
                    "timestamp[<>]" => [$startdate, $enddate]
                ]);
            }
        } else {
            $assets = getTableFiltered("assets", "clientid", $_GET['clientid']);
            $licenses = getTableFiltered("licenses", "clientid", $_GET['clientid']);
            if ($_GET['startDate'] == "" && $_GET['endDate'] == "") {
                $issues = $database->select("issues", "*", ["clientid" => $_GET['clientid']]);
                $tickets = $database->select("tickets", "*", ["clientid" => $_GET['clientid']]);
            } else {
                $issues = $database->select("issues", "*", ["AND" => [
                        "dateadded[<>]" => [$startdate, $enddate],
                        "clientid" => $_GET['clientid']
                ]]);
                $tickets = $database->select("tickets", "*", ["AND" => [
                        "timestamp[<>]" => [$startdate, $enddate],
                        "clientid" => $_GET['clientid']
                ]]);
            }
        }
    } elseif ($_GET['report'] == "summary") {
        if ($_GET['clientid'] == "0") {
            $assets = getTable("assets");
            $licenses = getTable("licenses");
        } else {
            $assets = getTableFiltered("assets", "clientid", $_GET['clientid']);
            $licenses = getTableFiltered("licenses", "clientid", $_GET['clientid']);
        }
    } elseif ($_GET['report'] == "userSummary") {
        if ($_GET['userid'] == "0") {
            $assets = getTable("assets");
        } else {
            $assets = getTableFiltered("assets", "userid", $_GET['userid']);
        }
    }


    $pageTitle = __("View Reports");
}

if ($route == "reports/assets") {
    isAuthorized("viewAssets");
    if ($isAdmin) {
        $assets = getTable("assets");
    } else {
        $assets = getTableFiltered("assets", "clientid", $liu['clientid']);
    }
    $pageTitle = __("Assets (Detailed List)");
}

if ($route == "reports/licenses") {
    isAuthorized("viewLicenses");
    if ($isAdmin) {
        $licenses = getTable("licenses");
    } else {
        $licenses = getTableFiltered("licenses", "clientid", $liu['clientid']);
    }
    $pageTitle = __("Licenses (Detailed List)");
}
//Licenses Expiry
if ($route == "reports/licenseexpiry") {
    isAuthorized("viewLicenses");
    if ($isAdmin) {
        $licenses = getTable("licenses","*","licenseexpirydate","ASC");
        $suppliers = getTable("suppliers");
        $clients = getTable("clients");
    } else {
        $licenses = getTableFiltered("licenses", "clientid", $liu['clientid']);
        $suppliers = getTable("suppliers");
        $clients = getTable("clients");
    }
    $pageTitle = __("Licenses Expiry");
}
//Web Services Expiry
if ($route == "reports/webserviceexpiry") {
    isAuthorized("viewLicenses");
    if ($isAdmin) {
        $webservices = getTable("webservices","*","expirydate","ASC");
        $suppliers = getTable("suppliers");
        $clients = getTable("clients");
        $accountnumbers = getTable("accountnumbers");
    } else {
        $webservices = getTableFiltered("webservices", "clientid", $liu['clientid']);
        $suppliers = getTable("suppliers");
        $clients = getTable("clients");
        $accountnumbers = getTable("accountnumbers");
    }
    $pageTitle = __("Web Services Expiry");
}

// CLIENTS
if ($route == "clients") {
    isAuthorized("viewClients");
    $clients = getTable("clients");
    $pageTitle = __("Clients");
}

if ($route == "clients/manage") {
    isAuthorized("manageClient");
    $client = getRowById("clients", $_GET['id']);
    $assets = getTableFiltered("assets", "clientid", $_GET['id']);
    $licenses = getTableFiltered("licenses", "clientid", $_GET['id']);
    $credentials = getTableFiltered("credentials", "clientid", $_GET['id']);
    $issues = getTableFiltered("issues", "clientid", $_GET['id']);
    $tickets = getTableFiltered("tickets", "clientid", $_GET['id'], "", "", "*", "id", "DESC");
    $users = getTableFiltered("people", "clientid", $_GET['id']);
    $admins = getTableFiltered("people", "type", "admin");
    $assignedadmins = getTableFiltered("clients_admins", "clientid", $_GET['id']);

    $sumAssets = countTableFiltered("assets", "clientid", $_GET['id']);
    $sumLicenses = countTableFiltered("licenses", "clientid", $_GET['id']);
    $sumCredentials = countTableFiltered("credentials", "clientid", $_GET['id']);
    $sumProjects = countTableFiltered("projects", "clientid", $_GET['id']);
    $sumUsers = countTableFiltered("people", "clientid", $_GET['id']);

    $categories = getTable("assetcategories");
    $files = getTableFiltered("files", "clientid", $_GET['id']);
    $projects = getTableFiltered("projects", "clientid", $_GET['id']);
    $pageTitle = $client['name'];
}


// STAFF
if ($route == "people/staff") {
    isAuthorized("viewStaff");
    $admins = getTableFiltered("people", "type", "admin");
    $pageTitle = __("Staff");
}
if ($route == "people/staff/edit") {
    isAuthorized("editStaff");
    $admin = getRowById("people", $_GET['id']);
    $languages = getTable("languages");
    $roles = getTableFiltered("roles", "type", "admin");
    $pageTitle = __("Edit Staff");
}


// USERS
if ($route == "people/users") {
    isAuthorized("viewUsers");
    if ($isAdmin)
        $users = getTableFiltered("people", "type", "user");
    else
        $users = getTableFiltered("people", "type", "user", "clientid", $liu['clientid']);
    $pageTitle = __("Users");
}

if ($route == "people/users/edit") {
    isAuthorized("editUser");
    $user = getRowById("people", $_GET['id']);
    $clients = getTable("clients");
    $languages = getTable("languages");
    $roles = getTableFiltered("roles", "type", "user");
    $pageTitle = __("Edit User");
}


// PROFILE
if ($route == "profile") {
    $languages = getTable("languages");
    $pageTitle = __("Profile");
}


// CONTACTS
if ($route == "people/contacts") {
    isAuthorized("viewContacts");
    $contacts = getTable("contacts");
    $pageTitle = __("Contacts");
}


// ROLES
if ($route == "people/roles") {
    isAuthorized("viewRoles");
    $roles = getTable("roles");
    $pageTitle = __("Roles");
}
if ($route == "people/roles/edit") {
    isAuthorized("editRole");
    $role = getRowById("roles", $_GET['id']);
    $roleperms = unserialize($role['perms']);
    $pageTitle = __("Edit Role");
}


// LABELS
if ($route == "inventory/attributes/labels") {
    isAuthorized("manageData");
    $labels = getTable("labels");
    $pageTitle = __("Labels");
}


// ASSET CATEGORIES
if ($route == "inventory/attributes/assetcategories") {
    isAuthorized("manageData");
    $categories = getTable("assetcategories");
    $pageTitle = __("Asset Categories");
}


// LICENSE CATEGORIES
if ($route == "inventory/attributes/licensecategories") {
    isAuthorized("manageData");
    $categories = getTable("licensecategories");
    $pageTitle = __("License Categories");
}


// MANUFACTURERS
if ($route == "inventory/attributes/manufacturers") {
    isAuthorized("manageData");
    $manufacturers = getTable("manufacturers");
    $pageTitle = __("Manufacturers");
}

// LOCATIONS
if ($route == "inventory/attributes/locations") {
    isAuthorized("manageData");
    if ($isAdmin) {
        $locations = getTable("locations");
    } else {
        $locations = getTableFiltered("locations", "clientid", $liu['clientid']);
    }
    $pageTitle = __("Locations");
}

// SUPPLIERS
if ($route == "inventory/attributes/suppliers") {
    isAuthorized("manageData");
    $suppliers = getTable("suppliers");
    $pageTitle = __("Suppliers");
}


// MODELS
if ($route == "inventory/attributes/models") {
    isAuthorized("manageData");
    $models = getTable("models");
    $pageTitle = __("Models");
}

// WEB SERVICES
if ($route == "inventory/webservices") {
    isAuthorized("viewLicenses");
    if ($isAdmin) {
        $webservices = getTable("webservices");
        $accountnumbers = getTable("accountnumbers");
        $accountids = $database->query("select distinct id from accountnumbers")->fetchAll();
    } else {
        $webservices = getTableFiltered("webservices", "clientid", $liu['clientid']);
        $accountnumbers = getTableFiltered("accountnumbers", "clientid", $liu['clientid']);
        $accountids = $database->query("select distinct id from accountnumbers")->fetchAll();
    }
    $pageTitle = __("Web Services");
}

if ($route == "inventory/webservices/manage") {
    isAuthorized("manageLicense");
    $webservice = getRowById("webservices", $_GET['id']);
    $categories = getTable("webservicecategories");
    $labels = getTable("labels");
    $clients = getTable("clients");
    $accountnumbers = getTable("accountnumbers");
    $suppliers = getTable("suppliers");
    $pageTitle = $webservice['id'];
}
if ($route == "inventory/webservices/create") {
    isAuthorized("addLicense");
    $suppliers = getTable("suppliers");
    $accountnumbers = getTable("accountnumbers");
    $categories = getTable("webservicecategories");
    $labels = getTable("labels");
    $clients = getTable("clients");
}

// WEB SERVICE CATEGORIES
if ($route == "inventory/attributes/webservicecategories") {
    isAuthorized("manageData");
    $categories = getTable("webservicecategories");
    $pageTitle = __("Web Service Categories");
}

// WEB SERVICE ACCOUNTS
if ($route == "inventory/attributes/accountnumbers") {
    isAuthorized("manageData");
    $accountnumbers = getTable("accountnumbers");
    $suppliers = getTable("suppliers");
    $pageTitle = __("Web Service Accounts");
}

// CALENDAR
if ($route == "calendar") {
    isAuthorized("viewIssues");
    if ($isAdmin) {
        if ($liu['id']== 2) {
            //$Issues = getTable("issues");
            $Issues = $database->select("issues","*", ["status[!]" => "Done"]);
            $admins = $database->select("people", ["id","name"], ["roleid[!]" => 2]);
        
        }else{
            $Issues = $database->select("issues","*", ["AND" => ["status[!]" => "Done","adminid" => $liu['id']]]);
        }
        $pageTitle = __("Calendar");
    }
}

if ($route == "mycalendar") {
    isAuthorized("viewIssues");
    if ($isAdmin) {
        //$Issues = getTable("issues");
        $Issues = $database->select("issues","*", ["AND" => ["status[!]" => "Done","adminid" => $liu['id']]]);
        //$admins = $database->select("people", ["id","name"], ["roleid[!]" => 2]);
        $projects = $database->select("projects","id",["managerid" => $liu['id']]);
        foreach ($projects as $project){
            if ($project['managerid'] == $liu['id']){ //if logged in user is project manager
                $teamIssues = $database->select("issues","*", ["AND" => ["adminid[!]" => $liu['id'],"projectid" => $project['id']]]); //retrieve issues with same project id and assigned to other admins
            }
        }
        foreach ($teamIssues as $teamIssue){ //for each issue assigned to other admins
            $admins = $database->select("people", ["id","name"], ["id" => $teamIssue['adminid']]); //get that admin's id and name
        }
    }
    $pageTitle = __("Calendar");
}

// LOGS
if ($route == "system/logs") {
    isAuthorized("viewLogs");
    $systemLog = getTable("systemlog");
    $emailLog = getTable("emaillog");
    $SMSLog = getTable("smslog");
    $pageTitle = __("Logs");
}


// SYSTEM SETTINGS
# predefined replies
if ($route == "system/preplies") {
    isAuthorized("viewPReplies");
    $preplies = getTable("tickets_pr");
    $pageTitle = __("Predefined Replies");
}

if ($route == "system/settings") {
    isAuthorized("manageSettings");
    $emailtemplates = getTable("emailTemplates");
    $languages = getTable("languages");
    $sdepartments = getTable("tickets_departments");
    $rules = getTableFiltered("tickets_rules", "ticketid", "0");
    $pageTitle = __("Settings");

    $tzlist = array(
        '(UTC-11:00) Midway Island' => 'Pacific/Midway',
        '(UTC-11:00) Samoa' => 'Pacific/Samoa',
        '(UTC-10:00) Hawaii' => 'Pacific/Honolulu',
        '(UTC-09:00) Alaska' => 'US/Alaska',
        '(UTC-08:00) Pacific Time (US &amp; Canada)' => 'America/Los_Angeles',
        '(UTC-08:00) Tijuana' => 'America/Tijuana',
        '(UTC-07:00) Arizona' => 'US/Arizona',
        '(UTC-07:00) Chihuahua' => 'America/Chihuahua',
        '(UTC-07:00) La Paz' => 'America/Chihuahua',
        '(UTC-07:00) Mazatlan' => 'America/Mazatlan',
        '(UTC-07:00) Mountain Time (US &amp; Canada)' => 'US/Mountain',
        '(UTC-06:00) Central America' => 'America/Managua',
        '(UTC-06:00) Central Time (US &amp; Canada)' => 'US/Central',
        '(UTC-06:00) Guadalajara' => 'America/Mexico_City',
        '(UTC-06:00) Mexico City' => 'America/Mexico_City',
        '(UTC-06:00) Monterrey' => 'America/Monterrey',
        '(UTC-06:00) Saskatchewan' => 'Canada/Saskatchewan',
        '(UTC-05:00) Bogota' => 'America/Bogota',
        '(UTC-05:00) Eastern Time (US &amp; Canada)' => 'US/Eastern',
        '(UTC-05:00) Indiana (East)' => 'US/East-Indiana',
        '(UTC-05:00) Lima' => 'America/Lima',
        '(UTC-05:00) Quito' => 'America/Bogota',
        '(UTC-04:00) Atlantic Time (Canada)' => 'Canada/Atlantic',
        '(UTC-04:30) Caracas' => 'America/Caracas',
        '(UTC-04:00) La Paz' => 'America/La_Paz',
        '(UTC-04:00) Santiago' => 'America/Santiago',
        '(UTC-03:30) Newfoundland' => 'Canada/Newfoundland',
        '(UTC-03:00) Brasilia' => 'America/Sao_Paulo',
        '(UTC-03:00) Buenos Aires' => 'America/Argentina/Buenos_Aires',
        '(UTC-03:00) Georgetown' => 'America/Argentina/Buenos_Aires',
        '(UTC-03:00) Greenland' => 'America/Godthab',
        '(UTC-02:00) Mid-Atlantic' => 'America/Noronha',
        '(UTC-01:00) Azores' => 'Atlantic/Azores',
        '(UTC-01:00) Cape Verde Is.' => 'Atlantic/Cape_Verde',
        '(UTC+00:00) Casablanca' => 'Africa/Casablanca',
        '(UTC+00:00) Edinburgh' => 'Europe/London',
        '(UTC+00:00) Greenwich Mean Time : Dublin' => 'Etc/Greenwich',
        '(UTC+00:00) Lisbon' => 'Europe/Lisbon',
        '(UTC+00:00) London' => 'Europe/London',
        '(UTC+00:00) Monrovia' => 'Africa/Monrovia',
        '(UTC+00:00) UTC' => 'UTC',
        '(UTC+01:00) Amsterdam' => 'Europe/Amsterdam',
        '(UTC+01:00) Belgrade' => 'Europe/Belgrade',
        '(UTC+01:00) Berlin' => 'Europe/Berlin',
        '(UTC+01:00) Bern' => 'Europe/Berlin',
        '(UTC+01:00) Bratislava' => 'Europe/Bratislava',
        '(UTC+01:00) Brussels' => 'Europe/Brussels',
        '(UTC+01:00) Budapest' => 'Europe/Budapest',
        '(UTC+01:00) Copenhagen' => 'Europe/Copenhagen',
        '(UTC+01:00) Ljubljana' => 'Europe/Ljubljana',
        '(UTC+01:00) Madrid' => 'Europe/Madrid',
        '(UTC+01:00) Paris' => 'Europe/Paris',
        '(UTC+01:00) Prague' => 'Europe/Prague',
        '(UTC+01:00) Rome' => 'Europe/Rome',
        '(UTC+01:00) Sarajevo' => 'Europe/Sarajevo',
        '(UTC+01:00) Skopje' => 'Europe/Skopje',
        '(UTC+01:00) Stockholm' => 'Europe/Stockholm',
        '(UTC+01:00) Vienna' => 'Europe/Vienna',
        '(UTC+01:00) Warsaw' => 'Europe/Warsaw',
        '(UTC+01:00) West Central Africa' => 'Africa/Lagos',
        '(UTC+01:00) Zagreb' => 'Europe/Zagreb',
        '(UTC+02:00) Athens' => 'Europe/Athens',
        '(UTC+02:00) Bucharest' => 'Europe/Bucharest',
        '(UTC+02:00) Cairo' => 'Africa/Cairo',
        '(UTC+02:00) Harare' => 'Africa/Harare',
        '(UTC+02:00) Helsinki' => 'Europe/Helsinki',
        '(UTC+02:00) Istanbul' => 'Europe/Istanbul',
        '(UTC+02:00) Jerusalem' => 'Asia/Jerusalem',
        '(UTC+02:00) Kyiv' => 'Europe/Helsinki',
        '(UTC+02:00) Pretoria' => 'Africa/Johannesburg',
        '(UTC+02:00) Riga' => 'Europe/Riga',
        '(UTC+02:00) Sofia' => 'Europe/Sofia',
        '(UTC+02:00) Tallinn' => 'Europe/Tallinn',
        '(UTC+02:00) Vilnius' => 'Europe/Vilnius',
        '(UTC+03:00) Baghdad' => 'Asia/Baghdad',
        '(UTC+03:00) Kuwait' => 'Asia/Kuwait',
        '(UTC+03:00) Minsk' => 'Europe/Minsk',
        '(UTC+03:00) Nairobi' => 'Africa/Nairobi',
        '(UTC+03:00) Riyadh' => 'Asia/Riyadh',
        '(UTC+03:00) Volgograd' => 'Europe/Volgograd',
        '(UTC+03:30) Tehran' => 'Asia/Tehran',
        '(UTC+04:00) Abu Dhabi' => 'Asia/Muscat',
        '(UTC+04:00) Baku' => 'Asia/Baku',
        '(UTC+04:00) Moscow' => 'Europe/Moscow',
        '(UTC+04:00) Muscat' => 'Asia/Muscat',
        '(UTC+04:00) St. Petersburg' => 'Europe/Moscow',
        '(UTC+04:00) Tbilisi' => 'Asia/Tbilisi',
        '(UTC+04:00) Yerevan' => 'Asia/Yerevan',
        '(UTC+04:30) Kabul' => 'Asia/Kabul',
        '(UTC+05:00) Islamabad' => 'Asia/Karachi',
        '(UTC+05:00) Karachi' => 'Asia/Karachi',
        '(UTC+05:00) Tashkent' => 'Asia/Tashkent',
        '(UTC+05:30) Chennai' => 'Asia/Calcutta',
        '(UTC+05:30) Kolkata' => 'Asia/Kolkata',
        '(UTC+05:30) Mumbai' => 'Asia/Calcutta',
        '(UTC+05:30) New Delhi' => 'Asia/Calcutta',
        '(UTC+05:30) Sri Jayawardenepura' => 'Asia/Calcutta',
        '(UTC+05:45) Kathmandu' => 'Asia/Katmandu',
        '(UTC+06:00) Almaty' => 'Asia/Almaty',
        '(UTC+06:00) Astana' => 'Asia/Dhaka',
        '(UTC+06:00) Dhaka' => 'Asia/Dhaka',
        '(UTC+06:00) Ekaterinburg' => 'Asia/Yekaterinburg',
        '(UTC+06:30) Rangoon' => 'Asia/Rangoon',
        '(UTC+07:00) Bangkok' => 'Asia/Bangkok',
        '(UTC+07:00) Hanoi' => 'Asia/Bangkok',
        '(UTC+07:00) Jakarta' => 'Asia/Jakarta',
        '(UTC+07:00) Novosibirsk' => 'Asia/Novosibirsk',
        '(UTC+08:00) Beijing' => 'Asia/Hong_Kong',
        '(UTC+08:00) Chongqing' => 'Asia/Chongqing',
        '(UTC+08:00) Hong Kong' => 'Asia/Hong_Kong',
        '(UTC+08:00) Krasnoyarsk' => 'Asia/Krasnoyarsk',
        '(UTC+08:00) Kuala Lumpur' => 'Asia/Kuala_Lumpur',
        '(UTC+08:00) Perth' => 'Australia/Perth',
        '(UTC+08:00) Singapore' => 'Asia/Singapore',
        '(UTC+08:00) Taipei' => 'Asia/Taipei',
        '(UTC+08:00) Ulaan Bataar' => 'Asia/Ulan_Bator',
        '(UTC+08:00) Urumqi' => 'Asia/Urumqi',
        '(UTC+09:00) Irkutsk' => 'Asia/Irkutsk',
        '(UTC+09:00) Osaka' => 'Asia/Tokyo',
        '(UTC+09:00) Sapporo' => 'Asia/Tokyo',
        '(UTC+09:00) Seoul' => 'Asia/Seoul',
        '(UTC+09:00) Tokyo' => 'Asia/Tokyo',
        '(UTC+09:30) Adelaide' => 'Australia/Adelaide',
        '(UTC+09:30) Darwin' => 'Australia/Darwin',
        '(UTC+10:00) Brisbane' => 'Australia/Brisbane',
        '(UTC+10:00) Canberra' => 'Australia/Canberra',
        '(UTC+10:00) Guam' => 'Pacific/Guam',
        '(UTC+10:00) Hobart' => 'Australia/Hobart',
        '(UTC+10:00) Melbourne' => 'Australia/Melbourne',
        '(UTC+10:00) Port Moresby' => 'Pacific/Port_Moresby',
        '(UTC+10:00) Sydney' => 'Australia/Sydney',
        '(UTC+10:00) Yakutsk' => 'Asia/Yakutsk',
        '(UTC+11:00) Vladivostok' => 'Asia/Vladivostok',
        '(UTC+12:00) Auckland' => 'Pacific/Auckland',
        '(UTC+12:00) Fiji' => 'Pacific/Fiji',
        '(UTC+12:00) International Date Line West' => 'Pacific/Kwajalein',
        '(UTC+12:00) Kamchatka' => 'Asia/Kamchatka',
        '(UTC+12:00) Magadan' => 'Asia/Magadan',
        '(UTC+12:00) Marshall Is.' => 'Pacific/Fiji',
        '(UTC+12:00) New Caledonia' => 'Asia/Magadan',
        '(UTC+12:00) Solomon Is.' => 'Asia/Magadan',
        '(UTC+12:00) Wellington' => 'Pacific/Auckland',
        '(UTC+13:00) Nuku\'alofa' => 'Pacific/Tongatapu'
    );
}
?>
