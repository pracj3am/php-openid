<?php
namespace Auth\OpenID\PAPE;

require_once "Auth/OpenID/PAPE.php";
require_once "Auth/OpenID/Extension.php";


/**
 * A Provider Authentication Policy request, sent from a relying party
 * to a provider
 *
 * preferred_auth_policies: The authentication policies that
 * the relying party prefers
 *
 * max_auth_age: The maximum time, in seconds, that the relying party
 * wants to allow to have elapsed before the user must re-authenticate
 */
class Request extends \Auth\OpenID\Extension {

    public $ns_alias = 'pape';
    public $ns_uri = NS_URI;

    public function __construct($preferred_auth_policies=null,
                                      $max_auth_age=null)
    {
        if ($preferred_auth_policies === null) {
            $preferred_auth_policies = array();
        }

        $this->preferred_auth_policies = $preferred_auth_policies;
        $this->max_auth_age = $max_auth_age;
    }

    /**
     * Add an acceptable authentication policy URI to this request
     *
     * This method is intended to be used by the relying party to add
     * acceptable authentication types to the request.
     *
     * policy_uri: The identifier for the preferred type of
     * authentication.
     */
    function addPolicyURI($policy_uri)
    {
        if (!in_array($policy_uri, $this->preferred_auth_policies)) {
            $this->preferred_auth_policies[] = $policy_uri;
        }
    }

    function getExtensionArgs()
    {
        $ns_args = array(
                         'preferred_auth_policies' =>
                           implode(' ', $this->preferred_auth_policies)
                         );

        if ($this->max_auth_age !== null) {
            $ns_args['max_auth_age'] = strval($this->max_auth_age);
        }

        return $ns_args;
    }

    /**
     * Instantiate a Request object from the arguments in a checkid_*
     * OpenID message
     */
    static function fromOpenIDRequest($request)
    {
        $obj = new Request();
        $args = $request->message->getArgs(NS_URI);

        if ($args === null || $args === array()) {
            return null;
        }

        $obj->parseExtensionArgs($args);
        return $obj;
    }

    /**
     * Set the state of this request to be that expressed in these
     * PAPE arguments
     *
     * @param args: The PAPE arguments without a namespace
     */
    function parseExtensionArgs($args)
    {
        // preferred_auth_policies is a space-separated list of policy
        // URIs
        $this->preferred_auth_policies = array();

        $policies_str = \Auth\OpenID::arrayGet($args, 'preferred_auth_policies');
        if ($policies_str) {
            foreach (explode(' ', $policies_str) as $uri) {
                if (!in_array($uri, $this->preferred_auth_policies)) {
                    $this->preferred_auth_policies[] = $uri;
                }
            }
        }

        // max_auth_age is base-10 integer number of seconds
        $max_auth_age_str = \Auth\OpenID::arrayGet($args, 'max_auth_age');
        if ($max_auth_age_str) {
            $this->max_auth_age = \Auth\OpenID::intval($max_auth_age_str);
        } else {
            $this->max_auth_age = null;
        }
    }

    /**
     * Given a list of authentication policy URIs that a provider
     * supports, this method returns the subsequence of those types
     * that are preferred by the relying party.
     *
     * @param supported_types: A sequence of authentication policy
     * type URIs that are supported by a provider
     *
     * @return array The sub-sequence of the supported types that are
     * preferred by the relying party. This list will be ordered in
     * the order that the types appear in the supported_types
     * sequence, and may be empty if the provider does not prefer any
     * of the supported authentication types.
     */
    function preferredTypes($supported_types)
    {
        $result = array();

        foreach ($supported_types as $st) {
            if (in_array($st, $this->preferred_auth_policies)) {
                $result[] = $st;
            }
        }
        return $result;
    }
}
