<?php
namespace Auth\OpenID\AX;

use Auth\OpenID\NamespaceMap;
use Auth\OpenID\TrustRoot;
use Auth\OpenID\AX;



/**
 * Require utility classes and functions for the consumer.
 */
require_once "Auth/OpenID/AX.php";
require_once "Auth/OpenID/Extension.php";
require_once "Auth/OpenID/Message.php";
require_once "Auth/OpenID/TrustRoot.php";


/**
 * Abstract class containing common code for attribute exchange
 * messages.
 *
 * @package OpenID
 */
abstract class Message extends \Auth\OpenID\Extension {
    /**
     * ns_alias: The preferred namespace alias for attribute exchange
     * messages
     */
    public $ns_alias = 'ax';

    /**
     * mode: The type of this attribute exchange message. This must be
     * overridden in subclasses.
     */
    public $mode = null;

    public $ns_uri = NS_URI;

    /**
     * Return \Auth\OpenID\AX\Error if the mode in the attribute
     * exchange arguments does not match what is expected for this
     * class; true otherwise.
     *
     * @access public
     */
    public function _checkMode($ax_args)
    {
        $mode = \Auth\OpenID::arrayGet($ax_args, 'mode');
        if ($mode != $this->mode) {
            return new Error(
                            sprintf(
                                    "Expected mode '%s'; got '%s'",
                                    $this->mode, $mode));
        }

        return true;
    }

    /**
     * Return a set of attribute exchange arguments containing the
     * basic information that must be in every attribute exchange
     * message.
     *
     * @access public
     */
    public function _newArgs()
    {
        return array('mode' => $this->mode);
    }
}



/**
 * An attribute exchange 'fetch_request' message. This message is sent
 * by a relying party when it wishes to obtain attributes about the
 * subject of an OpenID authentication request.
 *
 * @package OpenID
 */
class FetchRequest extends Message {

    public $mode = 'fetch_request';

    public function __construct($update_url=null)
    {
        /**
         * requested_attributes: The attributes that have been
         * requested thus far, indexed by the type URI.
         */
        $this->requested_attributes = array();

        /**
         * update_url: A URL that will accept responses for this
         * attribute exchange request, even in the absence of the user
         * who made this request.
        */
        $this->update_url = $update_url;
    }

    /**
     * Add an attribute to this attribute exchange request.
     *
     * @param attribute: The attribute that is being requested
     * @return true on success, false when the requested attribute is
     * already present in this fetch request.
     */
    function add($attribute)
    {
        if ($this->contains($attribute->type_uri)) {
            return new Error(
              sprintf("The attribute %s has already been requested",
                      $attribute->type_uri));
        }

        $this->requested_attributes[$attribute->type_uri] = $attribute;

        return true;
    }

    /**
     * Get the serialized form of this attribute fetch request.
     *
     * @returns FetchRequest The fetch request message parameters
     */
    function getExtensionArgs()
    {
        $aliases = new NamespaceMap();

        $required = array();
        $if_available = array();

        $ax_args = $this->_newArgs();

        foreach ($this->requested_attributes as $type_uri => $attribute) {
            if ($attribute->alias === null) {
                $alias = $aliases->add($type_uri);
            } else {
                $alias = $aliases->addAlias($type_uri, $attribute->alias);

                if ($alias === null) {
                    return new Error(
                      sprintf("Could not add alias %s for URI %s",
                              $attribute->alias, $type_uri
                      ));
                }
            }

            if ($attribute->required) {
                $required[] = $alias;
            } else {
                $if_available[] = $alias;
            }

            if ($attribute->count != 1) {
                $ax_args['count.' . $alias] = strval($attribute->count);
            }

            $ax_args['type.' . $alias] = $type_uri;
        }

        if ($required) {
            $ax_args['required'] = implode(',', $required);
        }

        if ($if_available) {
            $ax_args['if_available'] = implode(',', $if_available);
        }

        return $ax_args;
    }

    /**
     * Get the type URIs for all attributes that have been marked as
     * required.
     *
     * @return A list of the type URIs for attributes that have been
     * marked as required.
     */
    function getRequiredAttrs()
    {
        $required = array();
        foreach ($this->requested_attributes as $type_uri => $attribute) {
            if ($attribute->required) {
                $required[] = $type_uri;
            }
        }

        return $required;
    }

    /**
     * Extract a FetchRequest from an OpenID message
     *
     * @param request: The OpenID request containing the attribute
     * fetch request
     *
     * @returns mixed An \Auth\OpenID\AX\Error or the
     * \Auth\OpenID\AX\FetchRequest extracted from the request message if
     * successful
     */
    static function fromOpenIDRequest($request)
    {
        $m = $request->message;
        $obj = new FetchRequest();
        $ax_args = $m->getArgs($obj->ns_uri);

        $result = $obj->parseExtensionArgs($ax_args);

        if (AX::isError($result)) {
            return $result;
        }

        if ($obj->update_url) {
            // Update URL must match the openid.realm of the
            // underlying OpenID 2 message.
            $realm = $m->getArg(\Auth\OpenID\OPENID_NS, 'realm',
                        $m->getArg(
                                  \Auth\OpenID\OPENID_NS,
                                  'return_to'));

            if (!$realm) {
                $obj = new Error(
                  sprintf("Cannot validate update_url %s " .
                          "against absent realm", $obj->update_url));
            } else if (!TrustRoot::match($realm,
                                                     $obj->update_url)) {
                $obj = new Error(
                  sprintf("Update URL %s failed validation against realm %s",
                          $obj->update_url, $realm));
            }
        }

        return $obj;
    }

    /**
     * Given attribute exchange arguments, populate this FetchRequest.
     *
     * @return $result \Auth\OpenID\AX\Error if the data to be parsed
     * does not follow the attribute exchange specification. At least
     * when 'if_available' or 'required' is not specified for a
     * particular attribute type.  Returns true otherwise.
    */
    function parseExtensionArgs($ax_args)
    {
        $result = $this->_checkMode($ax_args);
        if (AX::isError($result)) {
            return $result;
        }

        $aliases = new NamespaceMap();

        foreach ($ax_args as $key => $value) {
            if (strpos($key, 'type.') === 0) {
                $alias = substr($key, 5);
                $type_uri = $value;

                $alias = $aliases->addAlias($type_uri, $alias);

                if ($alias === null) {
                    return new Error(
                      sprintf("Could not add alias %s for URI %s",
                              $alias, $type_uri)
                      );
                }

                $count_s = \Auth\OpenID::arrayGet($ax_args, 'count.' . $alias);
                if ($count_s) {
                    $count = \Auth\OpenID::intval($count_s);
                    if (($count === false) &&
                        ($count_s === UNLIMITED_VALUES)) {
                        $count = $count_s;
                    }
                } else {
                    $count = 1;
                }

                if ($count === false) {
                    return new Error(
                      sprintf("Integer value expected for %s, got %s",
                              'count.' . $alias, $count_s));
                }

                $attrinfo = AttrInfo::make($type_uri, $count,
                                                          false, $alias);

                if (AX::isError($attrinfo)) {
                    return $attrinfo;
                }

                $this->add($attrinfo);
            }
        }

        $required = toTypeURIs($aliases,
                         \Auth\OpenID::arrayGet($ax_args, 'required'));

        foreach ($required as $type_uri) {
            $attrib = $this->requested_attributes[$type_uri];
            $attrib->required = true;
        }

        $if_available = toTypeURIs($aliases,
                             \Auth\OpenID::arrayGet($ax_args, 'if_available'));

        $all_type_uris = array_merge($required, $if_available);

        foreach ($aliases->iterNamespaceURIs() as $type_uri) {
            if (!in_array($type_uri, $all_type_uris)) {
                return new Error(
                  sprintf('Type URI %s was in the request but not ' .
                          'present in "required" or "if_available"',
                          $type_uri));

            }
        }

        $this->update_url = \Auth\OpenID::arrayGet($ax_args, 'update_url');

        return true;
    }

    /**
     * Iterate over the AttrInfo objects that are contained in this
     * fetch_request.
     */
    function iterAttrs()
    {
        return array_values($this->requested_attributes);
    }

    function iterTypes()
    {
        return array_keys($this->requested_attributes);
    }

    /**
     * Is the given type URI present in this fetch_request?
     */
    function contains($type_uri)
    {
        return in_array($type_uri, $this->iterTypes());
    }
}

/**
 * An abstract class that implements a message that has attribute keys
 * and values. It contains the common code between fetch_response and
 * store_request.
 *
 * @package OpenID
 */
class KeyValueMessage extends Message {

    public function __construct()
    {
        $this->data = array();
    }

    /**
     * Add a single value for the given attribute type to the
     * message. If there are already values specified for this type,
     * this value will be sent in addition to the values already
     * specified.
     *
     * @param type_uri: The URI for the attribute
     * @param value: The value to add to the response to the relying
     * party for this attribute
     * @return null
     */
    function addValue($type_uri, $value)
    {
        if (!array_key_exists($type_uri, $this->data)) {
            $this->data[$type_uri] = array();
        }

        $values =& $this->data[$type_uri];
        $values[] = $value;
    }

    /**
     * Set the values for the given attribute type. This replaces any
     * values that have already been set for this attribute.
     *
     * @param type_uri: The URI for the attribute
     * @param values: A list of values to send for this attribute.
     */
    function setValues($type_uri, &$values)
    {
        $this->data[$type_uri] =& $values;
    }

    /**
     * Get the extension arguments for the key/value pairs contained
     * in this message.
     *
     * @param aliases: An alias mapping. Set to None if you don't care
     * about the aliases for this request.
     *
     * @access protected
     */
    protected function _getExtensionKVArgs($aliases)
    {
        if ($aliases === null) {
            $aliases = new NamespaceMap();
        }

        $ax_args = array();

        foreach ($this->data as $type_uri => $values) {
            $alias = $aliases->add($type_uri);

            $ax_args['type.' . $alias] = $type_uri;
            $ax_args['count.' . $alias] = strval(count($values));

            foreach ($values as $i => $value) {
              $key = sprintf('value.%s.%d', $alias, $i + 1);
              $ax_args[$key] = $value;
            }
        }

        return $ax_args;
    }

    /**
     * Parse attribute exchange key/value arguments into this object.
     *
     * @param ax_args: The attribute exchange fetch_response
     * arguments, with namespacing removed.
     *
     * @return Error or true
     */
    function parseExtensionArgs($ax_args)
    {
        $result = $this->_checkMode($ax_args);
        if (AX::isError($result)) {
            return $result;
        }

        $aliases = new NamespaceMap();

        foreach ($ax_args as $key => $value) {
            if (strpos($key, 'type.') === 0) {
                $type_uri = $value;
                $alias = substr($key, 5);

                $result = checkAlias($alias);

                if (AX::isError($result)) {
                    return $result;
                }

                $alias = $aliases->addAlias($type_uri, $alias);

                if ($alias === null) {
                    return new Error(
                      sprintf("Could not add alias %s for URI %s",
                              $alias, $type_uri)
                      );
                }
            }
        }

        foreach ($aliases->iteritems() as $pair) {
            list($type_uri, $alias) = $pair;

            if (array_key_exists('count.' . $alias, $ax_args) && ($ax_args['count.' . $alias] !== UNLIMITED_VALUES)) {

                $count_key = 'count.' . $alias;
                $count_s = $ax_args[$count_key];

                $count = \Auth\OpenID::intval($count_s);

                if ($count === false) {
                    return new Error(
                      sprintf("Integer value expected for %s, got %s",
                              'count. %s' . $alias, $count_s,
                              UNLIMITED_VALUES)
                                                    );
                }

                $values = array();
                for ($i = 1; $i < $count + 1; $i++) {
                    $value_key = sprintf('value.%s.%d', $alias, $i);

                    if (!array_key_exists($value_key, $ax_args)) {
                      return new Error(
                        sprintf(
                                "No value found for key %s",
                                $value_key));
                    }

                    $value = $ax_args[$value_key];
                    $values[] = $value;
                }
            } else {
                $key = 'value.' . $alias;

                if (!array_key_exists($key, $ax_args)) {
                  return new Error(
                    sprintf(
                            "No value found for key %s",
                            $key));
                }

                $value = $ax_args['value.' . $alias];

                if ($value == '') {
                    $values = array();
                } else {
                    $values = array($value);
                }
            }

            $this->data[$type_uri] = $values;
        }

        return true;
    }

    /**
     * Get a single value for an attribute. If no value was sent for
     * this attribute, use the supplied default. If there is more than
     * one value for this attribute, this method will fail.
     *
     * @param type_uri: The URI for the attribute
     * @param default: The value to return if the attribute was not
     * sent in the fetch_response.
     *
     * @return $value \Auth\OpenID\AX\Error on failure or the value of
     * the attribute in the fetch_response message, or the default
     * supplied
     */
    function getSingle($type_uri, $default=null)
    {
        $values = \Auth\OpenID::arrayGet($this->data, $type_uri);
        if (!$values) {
            return $default;
        } else if (count($values) == 1) {
            return $values[0];
        } else {
            return new Error(
              sprintf('More than one value present for %s',
                      $type_uri)
              );
        }
    }

    /**
     * Get the list of values for this attribute in the
     * fetch_response.
     *
     * XXX: what to do if the values are not present? default
     * parameter? this is funny because it's always supposed to return
     * a list, so the default may break that, though it's provided by
     * the user's code, so it might be okay. If no default is
     * supplied, should the return be None or []?
     *
     * @param type_uri: The URI of the attribute
     *
     * @return $values The list of values for this attribute in the
     * response. May be an empty list.  If the attribute was not sent
     * in the response, returns \Auth\OpenID\AX\Error.
     */
    function get($type_uri)
    {
        if (array_key_exists($type_uri, $this->data)) {
            return $this->data[$type_uri];
        } else {
            return new Error(
              sprintf("Type URI %s not found in response",
                      $type_uri)
              );
        }
    }

    /**
     * Get the number of responses for a particular attribute in this
     * fetch_response message.
     *
     * @param type_uri: The URI of the attribute
     *
     * @returns int The number of values sent for this attribute.  If
     * the attribute was not sent in the response, returns
     * \Auth\OpenID\AX\Error.
     */
    function count($type_uri)
    {
        if (array_key_exists($type_uri, $this->data)) {
            return count($this->get($type_uri));
        } else {
            return new Error(
              sprintf("Type URI %s not found in response",
                      $type_uri)
              );
        }
    }
}

/**
 * A fetch_response attribute exchange message.
 *
 * @package OpenID
 */
class FetchResponse extends KeyValueMessage {
    public $mode = 'fetch_response';

    public function __construct($update_url=null)
    {
        parent::__construct();
        $this->update_url = $update_url;
    }

    /**
     * Serialize this object into arguments in the attribute exchange
     * namespace
     *
     * @return $args The dictionary of unqualified attribute exchange
     * arguments that represent this fetch_response, or
     * Error on error.
     */
    function getExtensionArgs($request=null)
    {
        $aliases = new NamespaceMap();

        $zero_value_types = array();

        if ($request !== null) {
            // Validate the data in the context of the request (the
            // same attributes should be present in each, and the
            // counts in the response must be no more than the counts
            // in the request)

            foreach ($this->data as $type_uri => $unused) {
                if (!$request->contains($type_uri)) {
                    return new Error(
                      sprintf("Response attribute not present in request: %s",
                              $type_uri)
                      );
                }
            }

            foreach ($request->iterAttrs() as $attr_info) {
                // Copy the aliases from the request so that reading
                // the response in light of the request is easier
                if ($attr_info->alias === null) {
                    $aliases->add($attr_info->type_uri);
                } else {
                    $alias = $aliases->addAlias($attr_info->type_uri,
                                                $attr_info->alias);

                    if ($alias === null) {
                        return new Error(
                          sprintf("Could not add alias %s for URI %s",
                                  $attr_info->alias, $attr_info->type_uri)
                          );
                    }
                }

                if (array_key_exists($attr_info->type_uri, $this->data)) {
                    $values = $this->data[$attr_info->type_uri];
                } else {
                    $values = array();
                    $zero_value_types[] = $attr_info;
                }

                if (($attr_info->count != UNLIMITED_VALUES) &&
                    ($attr_info->count < count($values))) {
                    return new Error(
                      sprintf("More than the number of requested values " .
                              "were specified for %s",
                              $attr_info->type_uri)
                      );
                }
            }
        }

        $kv_args = $this->_getExtensionKVArgs($aliases);

        // Add the KV args into the response with the args that are
        // unique to the fetch_response
        $ax_args = $this->_newArgs();

        // For each requested attribute, put its type/alias and count
        // into the response even if no data were returned.
        foreach ($zero_value_types as $attr_info) {
            $alias = $aliases->getAlias($attr_info->type_uri);
            $kv_args['type.' . $alias] = $attr_info->type_uri;
            $kv_args['count.' . $alias] = '0';
        }

        $update_url = null;
        if ($request) {
            $update_url = $request->update_url;
        } else {
            $update_url = $this->update_url;
        }

        if ($update_url) {
            $ax_args['update_url'] = $update_url;
        }

        \Auth\OpenID::update($ax_args, $kv_args);

        return $ax_args;
    }

    /**
     * @return $result Error on failure or true on
     * success.
     */
    function parseExtensionArgs($ax_args)
    {
        $result = parent::parseExtensionArgs($ax_args);

        if (AX::isError($result)) {
            return $result;
        }

        $this->update_url = \Auth\OpenID::arrayGet($ax_args, 'update_url');

        return true;
    }

    /**
     * Construct a FetchResponse object from an OpenID library
     * SuccessResponse object.
     *
     * @param success_response: A successful id_res response object
     *
     * @param signed: Whether non-signed args should be processsed. If
     * True (the default), only signed arguments will be processsed.
     *
     * @return $response A FetchResponse containing the data from the
     * OpenID message
     */
    static function fromSuccessResponse($success_response, $signed=true)
    {
        $obj = new FetchResponse();
        if ($signed) {
            $ax_args = $success_response->getSignedNS($obj->ns_uri);
        } else {
            $ax_args = $success_response->message->getArgs($obj->ns_uri);
        }
        if ($ax_args === null || \Auth\OpenID::isFailure($ax_args) ||
              sizeof($ax_args) == 0) {
            return null;
        }

        $result = $obj->parseExtensionArgs($ax_args);
        if (AX::isError($result)) {
            #XXX log me
            return null;
        }
        return $obj;
    }
}

/**
 * A store request attribute exchange message representation.
 *
 * @package OpenID
 */
class StoreRequest extends KeyValueMessage {
    public $mode = 'store_request';

    /**
     * @param array $aliases The namespace aliases to use when making
     * this store response. Leave as None to use defaults.
     */
    function getExtensionArgs($aliases=null)
    {
        $ax_args = $this->_newArgs();
        $kv_args = $this->_getExtensionKVArgs($aliases);
        \Auth\OpenID::update($ax_args, $kv_args);
        return $ax_args;
    }
}

/**
 * An indication that the store request was processed along with this
 * OpenID transaction.  Use make(), NOT the constructor, to create
 * response objects.
 *
 * @package OpenID
 */
class StoreResponse extends Message {
    public $SUCCESS_MODE = 'store_response_success';
    public $FAILURE_MODE = 'store_response_failure';

    /**
     * Returns \Auth\OpenID\AX\Error on error or an
     * \Auth\OpenID\AX\StoreResponse object on success.
     */
    function make($succeeded=true, $error_message=null)
    {
        if (($succeeded) && ($error_message !== null)) {
            return new Error('An error message may only be '.
                                    'included in a failing fetch response');
        }

        return new StoreResponse($succeeded, $error_message);
    }

    public function __construct($succeeded=true, $error_message=null)
    {
        if ($succeeded) {
            $this->mode = $this->SUCCESS_MODE;
        } else {
            $this->mode = $this->FAILURE_MODE;
        }

        $this->error_message = $error_message;
    }

    /**
     * Was this response a success response?
     */
    function succeeded()
    {
        return $this->mode == $this->SUCCESS_MODE;
    }

    function getExtensionArgs()
    {
        $ax_args = $this->_newArgs();
        if ((!$this->succeeded()) && $this->error_message) {
            $ax_args['error'] = $this->error_message;
        }

        return $ax_args;
    }
}

