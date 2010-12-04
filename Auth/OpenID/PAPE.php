<?php
namespace Auth\OpenID;

/**
 * An implementation of the OpenID Provider Authentication Policy
 *  Extension 1.0
 *
 * See:
 * http://openid.net/developers/specs/
 */

require_once "Auth/OpenID/Extension.php";

define('Auth\OpenID\PAPE\NS_URI',
       "http://specs.openid.net/extensions/pape/1.0");

define('Auth\OpenID\PAPE\MULTI_FACTOR_PHYSICAL',
       'http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical');
define('Auth\OpenID\PAPE\MULTI_FACTOR',
       'http://schemas.openid.net/pape/policies/2007/06/multi-factor');
define('Auth\OpenID\PAPE\PHISHING_RESISTANT',
       'http://schemas.openid.net/pape/policies/2007/06/phishing-resistant');

define('Auth\OpenID\PAPE\TIME_VALIDATOR',
      '/^[0-9]{4,4}-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z$/');

