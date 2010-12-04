<?php
/**
 * This is the host that the store test will use
 */
global $_Auth_OpenID_memcache_test_host;
$_Auth_OpenID_memcache_test_host = 'localhost';

require_once dirname(__FILE__) . '/../Store.php';

class Tests_Auth_OpenID_MemcachedStore_Test extends Tests_Auth_OpenID_Store {

    function test_memcache()
    {
        // If the memcache extension isn't loaded or loadable, succeed
        // because we can't run the test.
        if (!extension_loaded('memcache')) {
            $this->markTestSkipped("skipping memcache store tests");
            return;
        }
        require_once 'Auth/OpenID/Store/Memcached.php';

        global $_Auth_OpenID_memcache_test_host;

        $memcached = new Memcache();
        if (!$memcached->connect($_Auth_OpenID_memcache_test_host)) {
            $this->fail("skipping memcache store tests - couldn't connect");
        } else {
            $store = new \Auth\OpenID\Store\Memcached(_$memcached);

            $this->_testStore($store);
            $this->_testNonce($store);
            $this->_testNonceCleanup($store);

            $memcached->close();
        }
    }
}
