<?php
namespace Auth\OpenID\AX;

use Auth\OpenID\AX;


require_once "Auth/OpenID/AX.php";

/**
 * Check an alias for invalid characters; raise AXError if any are
 * found.  Return None if the alias is valid.
 */
function checkAlias($alias)
{
  if (strpos($alias, ',') !== false) {
      return new Error(sprintf(
                   "Alias %s must not contain comma", $alias));
  }
  if (strpos($alias, '.') !== false) {
      return new Error(sprintf(
                   "Alias %s must not contain period", $alias));
  }

  return true;
}

/**
 * Results from data that does not meet the attribute exchange 1.0
 * specification
 *
 * @package OpenID
 */
class Error {
    public function __construct($message=null)
    {
        $this->message = $message;
    }
}


/**
 * Represents a single attribute in an attribute exchange
 * request. This should be added to an AXRequest object in order to
 * request the attribute.
 *
 * @package OpenID
 */
class AttrInfo {
    /**
     * Construct an attribute information object.  Do not call this
     * directly; call make(...) instead.
     *
     * @param string $type_uri The type URI for this attribute.
     *
     * @param int $count The number of values of this type to request.
     *
     * @param bool $required Whether the attribute will be marked as
     * required in the request.
     *
     * @param string $alias The name that should be given to this
     * attribute in the request.
     */
    public function __construct($type_uri, $count, $required,
                                     $alias)
    {
        /**
         * required: Whether the attribute will be marked as required
         * when presented to the subject of the attribute exchange
         * request.
         */
        $this->required = $required;

        /**
         * count: How many values of this type to request from the
         * subject. Defaults to one.
         */
        $this->count = $count;

        /**
         * type_uri: The identifier that determines what the attribute
         * represents and how it is serialized. For example, one type
         * URI representing dates could represent a Unix timestamp in
         * base 10 and another could represent a human-readable
         * string.
         */
        $this->type_uri = $type_uri;

        /**
         * alias: The name that should be given to this attribute in
         * the request. If it is not supplied, a generic name will be
         * assigned. For example, if you want to call a Unix timestamp
         * value 'tstamp', set its alias to that value. If two
         * attributes in the same message request to use the same
         * alias, the request will fail to be generated.
         */
        $this->alias = $alias;
    }

    /**
     * Construct an attribute information object.  For parameter
     * details, see the constructor.
     */
    static function make($type_uri, $count=1, $required=false,
                  $alias=null)
    {
        if ($alias !== null) {
            $result = checkAlias($alias);

            if (AX::isError($result)) {
                return $result;
            }
        }

        return new AttrInfo($type_uri, $count, $required,
                                           $alias);
    }

    /**
     * When processing a request for this attribute, the OP should
     * call this method to determine whether all available attribute
     * values were requested.  If self.count == UNLIMITED_VALUES, this
     * returns True.  Otherwise this returns False, in which case
     * self.count is an integer.
    */
    function wantsUnlimitedValues()
    {
        return $this->count === UNLIMITED_VALUES;
    }
}

/**
 * Given a namespace mapping and a string containing a comma-separated
 * list of namespace aliases, return a list of type URIs that
 * correspond to those aliases.
 *
 * @param $namespace_map The mapping from namespace URI to alias
 * @param $alias_list_s The string containing the comma-separated
 * list of aliases. May also be None for convenience.
 *
 * @return $seq The list of namespace URIs that corresponds to the
 * supplied list of aliases. If the string was zero-length or None, an
 * empty list will be returned.
 *
 * return null If an alias is present in the list of aliases but
 * is not present in the namespace map.
 */
function toTypeURIs($namespace_map, $alias_list_s)
{
    $uris = array();

    if ($alias_list_s) {
        foreach (explode(',', $alias_list_s) as $alias) {
            $type_uri = $namespace_map->getNamespaceURI($alias);
            if ($type_uri === null) {
                // raise KeyError(
                // 'No type is defined for attribute name %r' % (alias,))
                return new Error(
                  sprintf('No type is defined for attribute name %s',
                          $alias)
                  );
            } else {
                $uris[] = $type_uri;
            }
        }
    }

    return $uris;
}

