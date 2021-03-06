<?php
namespace Auth\OpenID;

/**
 * Extension argument processing code
 *
 * @package OpenID
 */

/**
 * Import tools needed to deal with messages.
 */
require_once 'Auth/OpenID.php';
require_once 'Auth/OpenID/KVForm.php';
require_once 'Auth/Yadis/XML.php';
require_once 'Auth/OpenID/Consumer.php'; // For \Auth\OpenID\FailureResponse

// This doesn't REALLY belong here, but where is better?
define('Auth\OpenID\IDENTIFIER_SELECT',
       "http://specs.openid.net/auth/2.0/identifier_select");

// URI for Simple Registration extension, the only commonly deployed
// OpenID 1.x extension, and so a special case
define('Auth\OpenID\SREG_URI', 'http://openid.net/sreg/1.0');

// The OpenID 1.X namespace URI
define('Auth\OpenID\OPENID1_NS', 'http://openid.net/signon/1.0');
define('Auth\OpenID\THE_OTHER_OPENID1_NS', 'http://openid.net/signon/1.1');

function isOpenID1($ns)
{
    return ($ns == THE_OTHER_OPENID1_NS) ||
        ($ns == OPENID1_NS);
}

// The OpenID 2.0 namespace URI
define('Auth\OpenID\OPENID2_NS', 'http://specs.openid.net/auth/2.0');

// The namespace consisting of pairs with keys that are prefixed with
// "openid."  but not in another namespace.
define('Auth\OpenID\NULL_NAMESPACE', 'Null namespace');

// The null namespace, when it is an allowed OpenID namespace
define('Auth\OpenID\OPENID_NS', 'OpenID namespace');

// The top-level namespace, excluding all pairs with keys that start
// with "openid."
define('Auth\OpenID\BARE_NS', 'Bare namespace');

// Sentinel for Message implementation to indicate that getArg should
// return null instead of returning a default.
define('Auth\OpenID\NO_DEFAULT', 'NO DEFAULT ALLOWED');

// Limit, in bytes, of identity provider and return_to URLs, including
// response payload.  See OpenID 1.1 specification, Appendix D.
define('Auth\OpenID\OPENID1_URL_LIMIT', 2047);

// All OpenID protocol fields.  Used to check namespace aliases.
global $Auth_OpenID_OPENID_PROTOCOL_FIELDS;
$Auth_OpenID_OPENID_PROTOCOL_FIELDS = array(
    'ns', 'mode', 'error', 'return_to', 'contact', 'reference',
    'signed', 'assoc_type', 'session_type', 'dh_modulus', 'dh_gen',
    'dh_consumer_public', 'claimed_id', 'identity', 'realm',
    'invalidate_handle', 'op_endpoint', 'response_nonce', 'sig',
    'assoc_handle', 'trust_root', 'openid');

// Global namespace / alias registration map.  See
// \Auth\OpenID\registerNamespaceAlias.
global $Auth_OpenID_registered_aliases;
$Auth_OpenID_registered_aliases = array();

/**
 * Registers a (namespace URI, alias) mapping in a global namespace
 * alias map.  Raises NamespaceAliasRegistrationError if either the
 * namespace URI or alias has already been registered with a different
 * value.  This function is required if you want to use a namespace
 * with an OpenID 1 message.
 */
function registerNamespaceAlias($namespace_uri, $alias)
{
    global $Auth_OpenID_registered_aliases;

    if (\Auth\OpenID::arrayGet($Auth_OpenID_registered_aliases,
                              $alias) == $namespace_uri) {
        return true;
    }

    if (in_array($namespace_uri,
                 array_values($Auth_OpenID_registered_aliases))) {
        return false;
    }

    if (in_array($alias, array_keys($Auth_OpenID_registered_aliases))) {
        return false;
    }

    $Auth_OpenID_registered_aliases[$alias] = $namespace_uri;
    return true;
}

/**
 * Removes a (namespace_uri, alias) registration from the global
 * namespace alias map.  Returns true if the removal succeeded; false
 * if not (if the mapping did not exist).
 */
function removeNamespaceAlias($namespace_uri, $alias)
{
    global $Auth_OpenID_registered_aliases;

    if (\Auth\OpenID::arrayGet($Auth_OpenID_registered_aliases,
                              $alias) === $namespace_uri) {
        unset($Auth_OpenID_registered_aliases[$alias]);
        return true;
    }

    return false;
}

/**
 * An \Auth\OpenID\Mapping maintains a mapping from arbitrary keys to
 * arbitrary values.  (This is unlike an ordinary PHP array, whose
 * keys may be only simple scalars.)
 *
 * @package OpenID
 */
class Mapping {
    /**
     * Initialize a mapping.  If $classic_array is specified, its keys
     * and values are used to populate the mapping.
     */
    public function __construct($classic_array = null)
    {
        $this->keys = array();
        $this->values = array();

        if (is_array($classic_array)) {
            foreach ($classic_array as $key => $value) {
                $this->set($key, $value);
            }
        }
    }

    /**
     * Returns true if $thing is an \Auth\OpenID\Mapping object; false
     * if not.
     */
    static function isA($thing)
    {
        return (is_object($thing) &&
                strtolower(get_class($thing)) == 'auth_openid_mapping');
    }

    /**
     * Returns an array of the keys in the mapping.
     */
    function keys()
    {
        return $this->keys;
    }

    /**
     * Returns an array of values in the mapping.
     */
    function values()
    {
        return $this->values;
    }

    /**
     * Returns an array of (key, value) pairs in the mapping.
     */
    function items()
    {
        $temp = array();

        for ($i = 0; $i < count($this->keys); $i++) {
            $temp[] = array($this->keys[$i],
                            $this->values[$i]);
        }
        return $temp;
    }

    /**
     * Returns the "length" of the mapping, or the number of keys.
     */
    function len()
    {
        return count($this->keys);
    }

    /**
     * Sets a key-value pair in the mapping.  If the key already
     * exists, its value is replaced with the new value.
     */
    function set($key, $value)
    {
        $index = array_search($key, $this->keys);

        if ($index !== false) {
            $this->values[$index] = $value;
        } else {
            $this->keys[] = $key;
            $this->values[] = $value;
        }
    }

    /**
     * Gets a specified value from the mapping, associated with the
     * specified key.  If the key does not exist in the mapping,
     * $default is returned instead.
     */
    function get($key, $default = null)
    {
        $index = array_search($key, $this->keys);

        if ($index !== false) {
            return $this->values[$index];
        } else {
            return $default;
        }
    }

    /**
     * @access private
     */
    private function _reflow()
    {
        // PHP is broken yet again.  Sort the arrays to remove the
        // hole in the numeric indexes that make up the array.
        $old_keys = $this->keys;
        $old_values = $this->values;

        $this->keys = array();
        $this->values = array();

        foreach ($old_keys as $k) {
            $this->keys[] = $k;
        }

        foreach ($old_values as $v) {
            $this->values[] = $v;
        }
    }

    /**
     * Deletes a key-value pair from the mapping with the specified
     * key.
     */
    function del($key)
    {
        $index = array_search($key, $this->keys);

        if ($index !== false) {
            unset($this->keys[$index]);
            unset($this->values[$index]);
            $this->_reflow();
            return true;
        }
        return false;
    }

    /**
     * Returns true if the specified value has a key in the mapping;
     * false if not.
     */
    function contains($value)
    {
        return (array_search($value, $this->keys) !== false);
    }
}

/**
 * Maintains a bijective map between namespace uris and aliases.
 *
 * @package OpenID
 */
class NamespaceMap {
    public function __construct()
    {
        $this->alias_to_namespace = new Mapping();
        $this->namespace_to_alias = new Mapping();
        $this->implicit_namespaces = array();
    }

    function getAlias($namespace_uri)
    {
        return $this->namespace_to_alias->get($namespace_uri);
    }

    function getNamespaceURI($alias)
    {
        return $this->alias_to_namespace->get($alias);
    }

    function iterNamespaceURIs()
    {
        // Return an iterator over the namespace URIs
        return $this->namespace_to_alias->keys();
    }

    function iterAliases()
    {
        // Return an iterator over the aliases"""
        return $this->alias_to_namespace->keys();
    }

    function iteritems()
    {
        return $this->namespace_to_alias->items();
    }

    function isImplicit($namespace_uri)
    {
        return in_array($namespace_uri, $this->implicit_namespaces);
    }

    function addAlias($namespace_uri, $desired_alias, $implicit=false)
    {
        // Add an alias from this namespace URI to the desired alias
        global $Auth_OpenID_OPENID_PROTOCOL_FIELDS;

        // Check that desired_alias is not an openid protocol field as
        // per the spec.
        if (in_array($desired_alias, $Auth_OpenID_OPENID_PROTOCOL_FIELDS)) {
            \Auth\OpenID::log("\"%s\" is not an allowed namespace alias",
                            $desired_alias);
            return null;
        }

        // Check that desired_alias does not contain a period as per
        // the spec.
        if (strpos($desired_alias, '.') !== false) {
            \Auth\OpenID::log('"%s" must not contain a dot', $desired_alias);
            return null;
        }

        // Check that there is not a namespace already defined for the
        // desired alias
        $current_namespace_uri =
            $this->alias_to_namespace->get($desired_alias);

        if (($current_namespace_uri !== null) &&
            ($current_namespace_uri != $namespace_uri)) {
            \Auth\OpenID::log('Cannot map "%s" because previous mapping exists',
                            $namespace_uri);
            return null;
        }

        // Check that there is not already a (different) alias for
        // this namespace URI
        $alias = $this->namespace_to_alias->get($namespace_uri);

        if (($alias !== null) && ($alias != $desired_alias)) {
            \Auth\OpenID::log('Cannot map %s to alias %s. ' .
                            'It is already mapped to alias %s',
                            $namespace_uri, $desired_alias, $alias);
            return null;
        }

        assert((NULL_NAMESPACE === $desired_alias) ||
               is_string($desired_alias));

        $this->alias_to_namespace->set($desired_alias, $namespace_uri);
        $this->namespace_to_alias->set($namespace_uri, $desired_alias);
        if ($implicit) {
            array_push($this->implicit_namespaces, $namespace_uri);
        }

        return $desired_alias;
    }

    function add($namespace_uri)
    {
        // Add this namespace URI to the mapping, without caring what
        // alias it ends up with

        // See if this namespace is already mapped to an alias
        $alias = $this->namespace_to_alias->get($namespace_uri);

        if ($alias !== null) {
            return $alias;
        }

        // Fall back to generating a numerical alias
        $i = 0;
        while (1) {
            $alias = 'ext' . strval($i);
            if ($this->addAlias($namespace_uri, $alias) === null) {
                $i += 1;
            } else {
                return $alias;
            }
        }

        // Should NEVER be reached!
        return null;
    }

    function contains($namespace_uri)
    {
        return $this->isDefined($namespace_uri);
    }

    function isDefined($namespace_uri)
    {
        return $this->namespace_to_alias->contains($namespace_uri);
    }
}

/**
 * In the implementation of this object, null represents the global
 * namespace as well as a namespace with no key.
 *
 * @package OpenID
 */
class Message {

    public function __construct($openid_namespace = null)
    {
        // Create an empty Message
        $this->allowed_openid_namespaces = array(
                               OPENID1_NS,
                               THE_OTHER_OPENID1_NS,
                               OPENID2_NS);

        $this->args = new Mapping();
        $this->namespaces = new NamespaceMap();
        if ($openid_namespace === null) {
            $this->_openid_ns_uri = null;
        } else {
            $implicit = isOpenID1($openid_namespace);
            $this->setOpenIDNamespace($openid_namespace, $implicit);
        }
    }

    function isOpenID1()
    {
        return isOpenID1($this->getOpenIDNamespace());
    }

    function isOpenID2()
    {
        return $this->getOpenIDNamespace() == OPENID2_NS;
    }

    static function fromPostArgs($args)
    {
        // Construct a Message containing a set of POST arguments
        $obj = new Message();

        // Partition into "openid." args and bare args
        $openid_args = array();
        foreach ($args as $key => $value) {

            if (is_array($value)) {
                return null;
            }

            $parts = explode('.', $key, 2);

            if (count($parts) == 2) {
                list($prefix, $rest) = $parts;
            } else {
                $prefix = null;
            }

            if ($prefix != 'openid') {
                $obj->args->set(array(BARE_NS, $key), $value);
            } else {
                $openid_args[$rest] = $value;
            }
        }

        if ($obj->_fromOpenIDArgs($openid_args)) {
            return $obj;
        } else {
            return null;
        }
    }

    static function fromOpenIDArgs($openid_args)
    {
        // Takes an array.

        // Construct a Message from a parsed KVForm message
        $obj = new Message();
        if ($obj->_fromOpenIDArgs($openid_args)) {
            return $obj;
        } else {
            return null;
        }
    }

    /**
     * @access private
     */
    private function _fromOpenIDArgs($openid_args)
    {
        global $Auth_OpenID_registered_aliases;

        // Takes an \Auth\OpenID\Mapping instance OR an array.

        if (!Mapping::isA($openid_args)) {
            $openid_args = new Mapping($openid_args);
        }

        $ns_args = array();

        // Resolve namespaces
        foreach ($openid_args->items() as $pair) {
            list($rest, $value) = $pair;

            $parts = explode('.', $rest, 2);

            if (count($parts) == 2) {
                list($ns_alias, $ns_key) = $parts;
            } else {
                $ns_alias = NULL_NAMESPACE;
                $ns_key = $rest;
            }

            if ($ns_alias == 'ns') {
                if ($this->namespaces->addAlias($value, $ns_key) === null) {
                    return false;
                }
            } else if (($ns_alias == NULL_NAMESPACE) &&
                       ($ns_key == 'ns')) {
                // null namespace
                if ($this->setOpenIDNamespace($value, false) === false) {
                    return false;
                }
            } else {
                $ns_args[] = array($ns_alias, $ns_key, $value);
            }
        }

        if (!$this->getOpenIDNamespace()) {
            if ($this->setOpenIDNamespace(OPENID1_NS, true) ===
                false) {
                return false;
            }
        }

        // Actually put the pairs into the appropriate namespaces
        foreach ($ns_args as $triple) {
            list($ns_alias, $ns_key, $value) = $triple;
            $ns_uri = $this->namespaces->getNamespaceURI($ns_alias);
            if ($ns_uri === null) {
                $ns_uri = $this->_getDefaultNamespace($ns_alias);
                if ($ns_uri === null) {

                    $ns_uri = OPENID_NS;
                    $ns_key = sprintf('%s.%s', $ns_alias, $ns_key);
                } else {
                    $this->namespaces->addAlias($ns_uri, $ns_alias, true);
                }
            }

            $this->setArg($ns_uri, $ns_key, $value);
        }

        return true;
    }

    private function _getDefaultNamespace($mystery_alias)
    {
        global $Auth_OpenID_registered_aliases;
        if ($this->isOpenID1()) {
            return @$Auth_OpenID_registered_aliases[$mystery_alias];
        }
        return null;
    }

    function setOpenIDNamespace($openid_ns_uri, $implicit)
    {
        if (!in_array($openid_ns_uri, $this->allowed_openid_namespaces)) {
            \Auth\OpenID::log('Invalid null namespace: "%s"', $openid_ns_uri);
            return false;
        }

        $succeeded = $this->namespaces->addAlias($openid_ns_uri,
                                                 NULL_NAMESPACE,
                                                 $implicit);
        if ($succeeded === false) {
            return false;
        }

        $this->_openid_ns_uri = $openid_ns_uri;

        return true;
    }

    function getOpenIDNamespace()
    {
        return $this->_openid_ns_uri;
    }

    static function fromKVForm($kvform_string)
    {
        // Create a Message from a KVForm string
        return Message::fromOpenIDArgs(
                     KVForm::toArray($kvform_string));
    }

    function copy()
    {
        return $this;
    }

    function toPostArgs()
    {
        // Return all arguments with openid. in front of namespaced
        // arguments.

        $args = array();

        // Add namespace definitions to the output
        foreach ($this->namespaces->iteritems() as $pair) {
            list($ns_uri, $alias) = $pair;
            if ($this->namespaces->isImplicit($ns_uri)) {
                continue;
            }
            if ($alias == NULL_NAMESPACE) {
                $ns_key = 'openid.ns';
            } else {
                $ns_key = 'openid.ns.' . $alias;
            }
            $args[$ns_key] = $ns_uri;
        }

        foreach ($this->args->items() as $pair) {
            list($ns_parts, $value) = $pair;
            list($ns_uri, $ns_key) = $ns_parts;
            $key = $this->getKey($ns_uri, $ns_key);
            $args[$key] = $value;
        }

        return $args;
    }

    function toArgs()
    {
        // Return all namespaced arguments, failing if any
        // non-namespaced arguments exist.
        $post_args = $this->toPostArgs();
        $kvargs = array();
        foreach ($post_args as $k => $v) {
            if (strpos($k, 'openid.') !== 0) {
                // raise ValueError(
                //   'This message can only be encoded as a POST, because it '
                //   'contains arguments that are not prefixed with "openid."')
                return null;
            } else {
                $kvargs[substr($k, 7)] = $v;
            }
        }

        return $kvargs;
    }

    function toFormMarkup($action_url, $form_tag_attrs = null,
                          $submit_text = "Continue")
    {
        $form = "<form accept-charset=\"UTF-8\" ".
            "enctype=\"application/x-www-form-urlencoded\"";

        if (!$form_tag_attrs) {
            $form_tag_attrs = array();
        }

        $form_tag_attrs['action'] = $action_url;
        $form_tag_attrs['method'] = 'post';

        unset($form_tag_attrs['enctype']);
        unset($form_tag_attrs['accept-charset']);

        if ($form_tag_attrs) {
            foreach ($form_tag_attrs as $name => $attr) {
                $form .= sprintf(" %s=\"%s\"", $name, $attr);
            }
        }

        $form .= ">\n";

        foreach ($this->toPostArgs() as $name => $value) {
            $form .= sprintf(
                        "<input type=\"hidden\" name=\"%s\" value=\"%s\" />\n",
                        $name, urldecode($value));
        }

        $form .= sprintf("<input type=\"submit\" value=\"%s\" />\n",
                         $submit_text);

        $form .= "</form>\n";

        return $form;
    }

    function toURL($base_url)
    {
        // Generate a GET URL with the parameters in this message
        // attached as query parameters.
        return \Auth\OpenID::appendArgs($base_url, $this->toPostArgs());
    }

    function toKVForm()
    {
        // Generate a KVForm string that contains the parameters in
        // this message. This will fail if the message contains
        // arguments outside of the 'openid.' prefix.
        return KVForm::fromArray($this->toArgs());
    }

    function toURLEncoded()
    {
        // Generate an x-www-urlencoded string
        $args = array();

        foreach ($this->toPostArgs() as $k => $v) {
            $args[] = array($k, $v);
        }

        sort($args);
        return \Auth\OpenID::httpBuildQuery($args);
    }

    /**
     * @access private
     */
    private function _fixNS($namespace)
    {
        // Convert an input value into the internally used values of
        // this object

        if ($namespace == OPENID_NS) {
            if ($this->_openid_ns_uri === null) {
                return new FailureResponse(null,
                    'OpenID namespace not set');
            } else {
                $namespace = $this->_openid_ns_uri;
            }
        }

        if (($namespace != BARE_NS) &&
              (!is_string($namespace))) {
            //TypeError
            $err_msg = sprintf("Namespace must be \Auth\OpenID\BARE_NS, ".
                              "\Auth\OpenID\OPENID_NS or a string. got %s",
                              print_r($namespace, true));
            return new FailureResponse(null, $err_msg);
        }

        if (($namespace != BARE_NS) &&
            (strpos($namespace, ':') === false)) {
            // fmt = 'OpenID 2.0 namespace identifiers SHOULD be URIs. Got %r'
            // warnings.warn(fmt % (namespace,), DeprecationWarning)

            if ($namespace == 'sreg') {
                // fmt = 'Using %r instead of "sreg" as namespace'
                // warnings.warn(fmt % (SREG_URI,), DeprecationWarning,)
                return SREG_URI;
            }
        }

        return $namespace;
    }

    function hasKey($namespace, $ns_key)
    {
        $namespace = $this->_fixNS($namespace);
        if (\Auth\OpenID::isFailure($namespace)) {
            // XXX log me
            return false;
        } else {
            return $this->args->contains(array($namespace, $ns_key));
        }
    }

    function getKey($namespace, $ns_key)
    {
        // Get the key for a particular namespaced argument
        $namespace = $this->_fixNS($namespace);
        if (\Auth\OpenID::isFailure($namespace)) {
            return $namespace;
        }
        if ($namespace == BARE_NS) {
            return $ns_key;
        }

        $ns_alias = $this->namespaces->getAlias($namespace);

        // No alias is defined, so no key can exist
        if ($ns_alias === null) {
            return null;
        }

        if ($ns_alias == NULL_NAMESPACE) {
            $tail = $ns_key;
        } else {
            $tail = sprintf('%s.%s', $ns_alias, $ns_key);
        }

        return 'openid.' . $tail;
    }

    function getArg($namespace, $key, $default = null)
    {
        // Get a value for a namespaced key.
        $namespace = $this->_fixNS($namespace);

        if (\Auth\OpenID::isFailure($namespace)) {
            return $namespace;
        } else {
            if ((!$this->args->contains(array($namespace, $key))) &&
              ($default == NO_DEFAULT)) {
                $err_msg = sprintf("Namespace %s missing required field %s",
                                   $namespace, $key);
                return new FailureResponse(null, $err_msg);
            } else {
                return $this->args->get(array($namespace, $key), $default);
            }
        }
    }

    function getArgs($namespace)
    {
        // Get the arguments that are defined for this namespace URI

        $namespace = $this->_fixNS($namespace);
        if (\Auth\OpenID::isFailure($namespace)) {
            return $namespace;
        } else {
            $stuff = array();
            foreach ($this->args->items() as $pair) {
                list($key, $value) = $pair;
                list($pair_ns, $ns_key) = $key;
                if ($pair_ns == $namespace) {
                    $stuff[$ns_key] = $value;
                }
            }

            return $stuff;
        }
    }

    function updateArgs($namespace, $updates)
    {
        // Set multiple key/value pairs in one call

        $namespace = $this->_fixNS($namespace);

        if (\Auth\OpenID::isFailure($namespace)) {
            return $namespace;
        } else {
            foreach ($updates as $k => $v) {
                $this->setArg($namespace, $k, $v);
            }
            return true;
        }
    }

    function setArg($namespace, $key, $value)
    {
        // Set a single argument in this namespace
        $namespace = $this->_fixNS($namespace);

        if (\Auth\OpenID::isFailure($namespace)) {
            return $namespace;
        } else {
            $this->args->set(array($namespace, $key), $value);
            if ($namespace !== BARE_NS) {
                $this->namespaces->add($namespace);
            }
            return true;
        }
    }

    function delArg($namespace, $key)
    {
        $namespace = $this->_fixNS($namespace);

        if (\Auth\OpenID::isFailure($namespace)) {
            return $namespace;
        } else {
            return $this->args->del(array($namespace, $key));
        }
    }

    function getAliasedArg($aliased_key, $default = null)
    {
        if ($aliased_key == 'ns') {
            // Return the namespace URI for the OpenID namespace
            return $this->getOpenIDNamespace();
        }

        $parts = explode('.', $aliased_key, 2);

        if (count($parts) != 2) {
            $ns = null;
        } else {
            list($alias, $key) = $parts;

            if ($alias == 'ns') {
              // Return the namespace URI for a namespace alias
              // parameter.
              return $this->namespaces->getNamespaceURI($key);
            } else {
              $ns = $this->namespaces->getNamespaceURI($alias);
            }
        }

        if ($ns === null) {
            $key = $aliased_key;
            $ns = $this->getOpenIDNamespace();
        }

        return $this->getArg($ns, $key, $default);
    }
}


