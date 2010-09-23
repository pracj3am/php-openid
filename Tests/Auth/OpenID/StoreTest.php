<?php
/**
 * A test script for the OpenIDStore classes.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: See the COPYING file included in this distribution.
 *
 * @package OpenID
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005-2008 Janrain, Inc.
 * @license http://www.apache.org/licenses/LICENSE-2.0 Apache
 */

/**
 * Require classes and functions to run the Store tests.
 * @ignore
 */
require_once 'Auth/OpenID/Association.php';
require_once 'Auth/OpenID/CryptUtil.php';
require_once 'Auth/OpenID/Nonce.php';
require_once 'Auth/OpenID.php';

function _Auth_OpenID_mkdtemp()
{
    if (strpos(PHP_OS, 'WIN') === 0) {
        $dir = $_ENV['TMP'];
        if (!isset($dir)) {
            $dir = 'C:\Windows\Temp';
        }
    } else {
        $dir = @$_ENV['TMPDIR'];
        if (!isset($dir)) {
            $dir = '/tmp';
        }
    }

    return Auth_OpenID_Store_File::_mkdtemp($dir);
}

/**
 * Generate a sufficently unique database name so many hosts can run
 * SQL store tests on the server at the same time and not step on each
 * other.
 */
function _Auth_OpenID_getTmpDbName()
{
    $hostname = php_uname('n');
    $hostname = str_replace('.', '_', $hostname);
    $hostname = str_replace('-', '_', $hostname);
    $hostname = strtolower($hostname);

    return sprintf("%s_%d_%s_openid_test",
                   $hostname,
                   getmypid(),
                   strval(rand(1, time())));
}

/**
 * Hub test suite class
 */
class Tests_Auth_OpenID_StoreTest extends PHPUnit_Framework_TestSuite
{
    function suite()
    {
        require_once dirname(__FILE__) . '/MemcachedStore/Test.php';
        require_once dirname(__FILE__) . '/Included/StoreTest.php';

        $suite = new PHPUnit_Framework_TestSuite("Tests_Auth_OpenID_StoreTest");
    
        $suite->addTestSuite('Tests_Auth_OpenID_Included_StoreTest');
        $suite->addTestSuite('Tests_Auth_OpenID_MemcachedStore_Test');

        return $suite;
    }
}

