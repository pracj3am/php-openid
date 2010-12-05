<?php
namespace Auth\OpenID\PAPE;

require_once "Auth/OpenID/PAPE.php";
require_once "Auth/OpenID/Extension.php";

/**
 * A Provider Authentication Policy response, sent from a provider to
 * a relying party
 */
class Response extends \Auth\OpenID\Extension {

    public $ns_alias = 'pape';
    public $ns_uri = NS_URI;

    public $auth_policies;
    public $auth_time;
    public $nist_auth_level;

    public function __construct($auth_policies=null, $auth_time=null,
                                       $nist_auth_level=null)
    {
        if ($auth_policies) {
            $this->auth_policies = $auth_policies;
        } else {
            $this->auth_policies = array();
        }

        $this->auth_time = $auth_time;
        $this->nist_auth_level = $nist_auth_level;
    }

    /**
     * Add a authentication policy to this response
     *
     * This method is intended to be used by the provider to add a
     * policy that the provider conformed to when authenticating the
     * user.
     *
     * @param policy_uri: The identifier for the preferred type of
     * authentication.
     */
    function addPolicyURI($policy_uri)
    {
        if (!in_array($policy_uri, $this->auth_policies)) {
            $this->auth_policies[] = $policy_uri;
        }
    }

    /**
     * Create an PAPE_Response object from a successful
     * OpenID library response.
     *
     * @param success_response $success_response A SuccessResponse
     * from \Auth\OpenID\Consumer::complete()
     *
     * @returns: A provider authentication policy response from the
     * data that was supplied with the id_res response.
     */
    static function fromSuccessResponse($success_response)
    {
        $obj = new Response();

        // PAPE requires that the args be signed.
        $args = $success_response->getSignedNS(NS_URI);

        if ($args === null || $args === array()) {
            return null;
        }

        $result = $obj->parseExtensionArgs($args);

        if ($result === false) {
            return null;
        } else {
            return $obj;
        }
    }

    /**
     * Parse the provider authentication policy arguments into the
     *  internal state of this object
     *
     * @param args: unqualified provider authentication policy
     * arguments
     *
     * @param strict: Whether to return false when bad data is
     * encountered
     *
     * @return null The data is parsed into the internal fields of
     * this object.
    */
    function parseExtensionArgs($args, $strict=false)
    {
        $policies_str = \Auth\OpenID::arrayGet($args, 'auth_policies');
        if ($policies_str && $policies_str != "none") {
            $this->auth_policies = explode(" ", $policies_str);
        }

        $nist_level_str = \Auth\OpenID::arrayGet($args, 'nist_auth_level');
        if ($nist_level_str !== null) {
            $nist_level = \Auth\OpenID::intval($nist_level_str);

            if ($nist_level === false) {
                if ($strict) {
                    return false;
                } else {
                    $nist_level = null;
                }
            }

            if (0 <= $nist_level && $nist_level < 5) {
                $this->nist_auth_level = $nist_level;
            } else if ($strict) {
                return false;
            }
        }

        $auth_time = \Auth\OpenID::arrayGet($args, 'auth_time');
        if ($auth_time !== null) {
            if (preg_match(TIME_VALIDATOR, $auth_time)) {
                $this->auth_time = $auth_time;
            } else if ($strict) {
                return false;
            }
        }
    }

    function getExtensionArgs()
    {
        $ns_args = array();
        if (count($this->auth_policies) > 0) {
            $ns_args['auth_policies'] = implode(' ', $this->auth_policies);
        } else {
            $ns_args['auth_policies'] = 'none';
        }

        if ($this->nist_auth_level !== null) {
            if (!in_array($this->nist_auth_level, range(0, 4), true)) {
                return false;
            }
            $ns_args['nist_auth_level'] = strval($this->nist_auth_level);
        }

        if ($this->auth_time !== null) {
            if (!preg_match(TIME_VALIDATOR, $this->auth_time)) {
                return false;
            }

            $ns_args['auth_time'] = $this->auth_time;
        }

        return $ns_args;
    }
}
