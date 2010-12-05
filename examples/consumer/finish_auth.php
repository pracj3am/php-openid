<?php

require_once "common.php";
session_start();

function escape($thing) {
    return htmlentities($thing);
}

function run() {
    $consumer = getConsumer();

    // Complete the authentication process using the server's
    // response.
    $return_to = getReturnTo();
    $response = $consumer->complete($return_to);

    // Check the response status.
    if ($response->status == \Auth\OpenID\CANCEL) {
        // This means the authentication was cancelled.
        $msg = 'Verification cancelled.';
    } else if ($response->status == \Auth\OpenID\FAILURE) {
        // Authentication failed; display the error message.
        $msg = "OpenID authentication failed: " . $response->message;
    } else if ($response->status == \Auth\OpenID\SUCCESS) {
        // This means the authentication succeeded; extract the
        // identity URL and Simple Registration data (if it was
        // returned).
        $openid = $response->getDisplayIdentifier();
        $esc_identity = escape($openid);

        $success = sprintf('You have successfully verified ' .
                           '<a href="%s">%s</a> as your identity.',
                           $esc_identity, $esc_identity);

        if ($response->endpoint->canonicalID) {
            $escaped_canonicalID = escape($response->endpoint->canonicalID);
            $success .= '  (XRI CanonicalID: '.$escaped_canonicalID.') ';
        }

        $sreg_resp = \Auth\OpenID\SRegResponse::fromSuccessResponse($response);

        $sreg = $sreg_resp->contents();

        if (@$sreg['email']) {
            $success .= "  You also returned '".escape($sreg['email']).
                "' as your email.";
        }

        if (@$sreg['nickname']) {
            $success .= "  Your nickname is '".escape($sreg['nickname']).
                "'.";
        }

        if (@$sreg['fullname']) {
            $success .= "  Your fullname is '".escape($sreg['fullname']).
                "'.";
        }

	$pape_resp = \Auth\OpenID\PAPE\Response::fromSuccessResponse($response);

	if ($pape_resp) {
            if ($pape_resp->auth_policies) {
                $success .= "<p>The following PAPE policies affected the authentication:</p><ul>";

                foreach ($pape_resp->auth_policies as $uri) {
                    $escaped_uri = escape($uri);
                    $success .= "<li><tt>$escaped_uri</tt></li>";
                }

                $success .= "</ul>";
            } else {
                $success .= "<p>No PAPE policies affected the authentication.</p>";
            }

            if ($pape_resp->auth_time) {
                $age = escape($pape_resp->auth_time);
                $success .= "<p>The authentication age returned by the " .
                    "server is: <tt>".$age."</tt></p>";
            }

            if ($pape_resp->nist_auth_level) {
                $auth_level = escape($pape_resp->nist_auth_level);
                $success .= "<p>The NIST auth level returned by the " .
                    "server is: <tt>".$auth_level."</tt></p>";
            }

	} else {
            $success .= "<p>No PAPE response was sent by the provider.</p>";
	}
    }

    include 'index.php';
}

run();

?>