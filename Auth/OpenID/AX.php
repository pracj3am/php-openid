<?php
namespace Auth\OpenID;
/**
 * Implements the OpenID attribute exchange specification, version 1.0
 * as of svn revision 370 from openid.net svn.
 *
 * @package OpenID
 */


define('Auth\OpenID\AX\NS_URI',
       'http://openid.net/srv/ax/1.0');

// Use this as the 'count' value for an attribute in a FetchRequest to
// ask for as many values as the OP can provide.
define('Auth\OpenID\AX\UNLIMITED_VALUES', 'unlimited');

// Minimum supported alias length in characters.  Here for
// completeness.
define('Auth\OpenID\AX\MINIMUM_SUPPORTED_ALIAS_LENGTH', 32);

/**
 * AX utility class.
 *
 * @package OpenID
 */
class AX {
    /**
     * @param mixed $thing Any object which may be an
     * \Auth\OpenID\AX\Error object.
     *
     * @return bool true if $thing is an \Auth\OpenID\AX\Error; false
     * if not.
     */
    static function isError($thing)
    {
        return is_a($thing, '\Auth\OpenID\AX\Error');
    }
}
